package main

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type udpSession struct {
	clientAddr   *net.UDPAddr
	targetConn   *net.UDPConn
	lastActivity time.Time
	connID       int64
}

type ForwarderManager struct {
	mu                  sync.Mutex
	activeListeners     map[string][]net.Listener
	activeUDPConns      map[string][]*net.UDPConn
	tcpConnectionCounts map[string]int
	connManager         *ConnectionManager
	ipFilterManager     *IPFilterManager
	cancelFuncs         map[string]context.CancelFunc
	ruleStatus          map[string]string // Tracks runtime status ("running", "stopped", "error")
}

func NewForwarderManager(connManager *ConnectionManager, ipFilterManager *IPFilterManager) *ForwarderManager {
	return &ForwarderManager{
		activeListeners:     make(map[string][]net.Listener),
		activeUDPConns:      make(map[string][]*net.UDPConn),
		tcpConnectionCounts: make(map[string]int),
		connManager:         connManager,
		ipFilterManager:     ipFilterManager,
		cancelFuncs:         make(map[string]context.CancelFunc),
		ruleStatus:          make(map[string]string),
	}
}

func (fm *ForwarderManager) StartRule(rule Rule) {
	if !rule.Enabled {
		fm.mu.Lock()
		fm.ruleStatus[rule.Name] = "stopped"
		fm.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	fm.mu.Lock()
	fm.cancelFuncs[rule.Name] = cancel
	fm.tcpConnectionCounts[rule.Name] = 0
	fm.mu.Unlock()

	proto := strings.ToLower(rule.Protocol)

	successChannel := make(chan bool, 2)
	var startedListeners int

	if strings.Contains(proto, "tcp") {
		startedListeners++
		go func() {
			successChannel <- fm.startTCPForwarder(ctx, rule)
		}()
	}
	if strings.Contains(proto, "udp") {
		startedListeners++
		go func() {
			successChannel <- fm.startUDPForwarder(ctx, rule)
		}()
	}

	atLeastOneSuccess := false
	allSuccess := true
	for i := 0; i < startedListeners; i++ {
		success := <-successChannel
		if success {
			atLeastOneSuccess = true
		} else {
			allSuccess = false
		}
	}
	
	// **FIX**: If not all listeners started successfully, it's an error.
	if !allSuccess {
		// If at least one listener *did* succeed (partial failure), we need to stop it.
		if atLeastOneSuccess {
			log.Printf("[Manager] 规则 [%s] 部分启动失败，正在停止已成功的部分...", rule.Name)
			// Calling StopRule will clean up everything and set status to "stopped".
			fm.StopRule(rule.Name) 
		}
		// Regardless of partial success, the final state is an error.
		fm.mu.Lock()
		fm.ruleStatus[rule.Name] = "error"
		fm.mu.Unlock()
	} else {
        fm.mu.Lock()
		fm.ruleStatus[rule.Name] = "running"
        fm.mu.Unlock()
	}
}


func (fm *ForwarderManager) StopRule(ruleName string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if cancel, ok := fm.cancelFuncs[ruleName]; ok {
		cancel()
		delete(fm.cancelFuncs, ruleName)
	}
	if listeners, ok := fm.activeListeners[ruleName]; ok {
		for _, l := range listeners {
			l.Close()
		}
		delete(fm.activeListeners, ruleName)
		log.Printf("[Manager] 已停止规则 [%s] 的TCP监听。", ruleName)
	}
	if conns, ok := fm.activeUDPConns[ruleName]; ok {
		for _, conn := range conns {
			conn.Close()
		}
		delete(fm.activeUDPConns, ruleName)
		log.Printf("[Manager] 已停止规则 [%s] 的UDP监听。", ruleName)
	}
	delete(fm.tcpConnectionCounts, ruleName)
	fm.ruleStatus[ruleName] = "stopped"
}

// GetRuleStatuses returns the current runtime status of all port forwarding rules.
func (fm *ForwarderManager) GetRuleStatuses(rules []Rule) map[string]string {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	statuses := make(map[string]string)
	for _, rule := range rules {
		if status, ok := fm.ruleStatus[rule.Name]; ok {
			if !rule.Enabled {
				statuses[rule.Name] = "stopped"
			} else {
				statuses[rule.Name] = status
			}
		} else {
			if rule.Enabled {
				statuses[rule.Name] = "error" 
			} else {
				statuses[rule.Name] = "stopped"
			}
		}
	}
	return statuses
}


func (fm *ForwarderManager) startTCPForwarder(ctx context.Context, rule Rule) bool {
	protocol := "tcp"
	if rule.ListenAddr == "0.0.0.0" {
		protocol = "tcp4"
	} else if rule.ListenAddr == "::" {
		protocol = "tcp6"
	}
	
	listener, err := net.Listen(protocol, rule.ListenAddress())
	if err != nil {
		log.Printf("错误: 无法为规则 [%s] 监听TCP端口 %s (%s): %v", rule.Name, rule.ListenAddress(), protocol, err)
		return false
	}

	fm.mu.Lock()
	fm.activeListeners[rule.Name] = append(fm.activeListeners[rule.Name], listener)
	fm.mu.Unlock()
	log.Printf("==== 规则 [%s] 已启动并成功监听TCP在 %s (%s) ====", rule.Name, rule.ListenAddress(), protocol)
	
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
				default:
					log.Printf("规则 [%s] 的TCP监听出现错误: %v", rule.Name, err)
				}
				return
			}
			go fm.handleTCPConnection(clientConn, rule)
		}
	}()

	return true
}

func (fm *ForwarderManager) handleTCPConnection(clientConn net.Conn, rule Rule) {
	defer clientConn.Close()

	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]
	allowed, reason := fm.ipFilterManager.IsAllowed(clientIP, rule.AccessControl)
	if !allowed {
		log.Printf("[%s] 已拒绝来自 %s 的连接: %s", rule.Name, clientIP, reason)
		return
	}

	fm.mu.Lock()
	connLimit := rule.ConnectionLimit
	if connLimit == 0 {
		connLimit = 256
	}
	if fm.tcpConnectionCounts[rule.Name] >= connLimit {
		fm.mu.Unlock()
		log.Printf("[%s] 已达到连接数限制 (%d)，拒绝来自 %s 的新连接", rule.Name, connLimit, clientIP)
		return
	}
	fm.tcpConnectionCounts[rule.Name]++
	fm.mu.Unlock()

	defer func() {
		fm.mu.Lock()
		fm.tcpConnectionCounts[rule.Name]--
		fm.mu.Unlock()
	}()

	connID := fm.connManager.Add("TCP", rule.Name, clientConn, nil)
	fm.connManager.Broadcast()

	defer func() {
		fm.connManager.Remove(connID)
	}()
	
	targetConn, err := net.Dial("tcp", rule.ForwardAddress())
	if err != nil {
		log.Printf("[%s] 无法连接到TCP目标 %s: %v", rule.Name, rule.ForwardAddress(), err)
		return
	}
	defer targetConn.Close()

	fm.connManager.UpdateTargetConn(connID, targetConn)
	fm.connManager.Broadcast()
	log.Printf("[%s] TCP 连接已建立: %s <-> %s", rule.Name, clientConn.RemoteAddr(), targetConn.RemoteAddr())
	
	var wg sync.WaitGroup
	wg.Add(2)

	rateLimit := rule.RateLimit
	var limitedClientConn io.ReadWriter
	if rateLimit > 0 {
		limit := rate.Limit(rateLimit * 1024)
		limiter := rate.NewLimiter(limit, int(limit))
		limitedClientConn = NewRateLimitedConn(clientConn, limiter, limiter)
	} else {
		limitedClientConn = clientConn
	}

	go func() {
		defer wg.Done()
		io.Copy(targetConn, limitedClientConn)
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(limitedClientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()
	
	wg.Wait()
}


func (fm *ForwarderManager) startUDPForwarder(ctx context.Context, rule Rule) bool {
	protocol := "udp"
	if rule.ListenAddr == "0.0.0.0" {
		protocol = "udp4"
	} else if rule.ListenAddr == "::" {
		protocol = "udp6"
	}

	listenAddr, err := net.ResolveUDPAddr(protocol, rule.ListenAddress())
	if err != nil {
		log.Printf("错误: 无法解析UDP监听地址 [%s] (%s): %v", rule.Name, rule.ListenAddress(), protocol, err)
		return false
	}
	conn, err := net.ListenUDP(protocol, listenAddr)
	if err != nil {
		log.Printf("错误: 无法为规则 [%s] 监听UDP端口 %s (%s): %v", rule.Name, rule.ListenAddress(), protocol, err)
		return false
	}
	fm.mu.Lock()
	fm.activeUDPConns[rule.Name] = append(fm.activeUDPConns[rule.Name], conn)
	fm.mu.Unlock()
	log.Printf("==== 规则 [%s] 已启动并成功监听UDP在 %s (%s) ====", rule.Name, rule.ListenAddress(), protocol)
	
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	go func() {
		sessions := make(map[string]*udpSession)
		var mu sync.Mutex

		timeout := time.Duration(rule.UDPSessionTimeout) * time.Millisecond
		if timeout == 0 {
			timeout = 30000 * time.Millisecond
		}
		maxSessions := rule.UDPMaxSessions
		if maxSessions == 0 {
			maxSessions = 32
		}
		maxBlockLength := rule.UDPMaxBlockLength
		if maxBlockLength == 0 {
			maxBlockLength = 1500
		}

		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					mu.Lock()
					for key, session := range sessions {
						if time.Since(session.lastActivity) > timeout {
							session.targetConn.Close()
							delete(sessions, key)
							fm.connManager.Remove(session.connID)
						}
					}
					mu.Unlock()
				case <-ctx.Done():
					return
				}
			}
		}()

		buf := make([]byte, maxBlockLength)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
				default:
					log.Printf("规则 [%s] 的UDP监听出现错误: %v", rule.Name, err)
				}
				return
			}
			
			clientIP := clientAddr.IP.String()
			allowed, reason := fm.ipFilterManager.IsAllowed(clientIP, rule.AccessControl)
			if !allowed {
				log.Printf("[%s] 已拒绝来自 %s 的UDP数据包: %s", rule.Name, clientIP, reason)
				continue
			}

			mu.Lock()
			session, found := sessions[clientAddr.String()]
			if !found {
				if len(sessions) >= maxSessions {
					mu.Unlock()
					log.Printf("[%s] 已达到UDP会话数限制 (%d)，拒绝来自 %s 的新会话", rule.Name, maxSessions, clientIP)
					continue
				}
				
				targetAddr, err := net.ResolveUDPAddr("udp", rule.ForwardAddress())
				if err != nil {
					log.Printf("[%s] 无法解析UDP目标地址: %v", rule.Name, err)
					mu.Unlock()
					continue
				}
				targetConn, err := net.DialUDP("udp", nil, targetAddr)
				if err != nil {
					log.Printf("[%s] 无法连接UDP目标: %v", rule.Name, err)
					mu.Unlock()
					continue
				}

				connID := fm.connManager.Add("UDP", rule.Name, nil, targetConn)
				fm.connManager.connections[connID].ClientAddr = clientAddr.String()
				fm.connManager.Broadcast()

				session = &udpSession{
					clientAddr:   clientAddr,
					targetConn:   targetConn,
					lastActivity: time.Now(),
					connID:       connID,
				}
				sessions[clientAddr.String()] = session

				go func(s *udpSession) {
					readBuf := make([]byte, maxBlockLength)
					for {
						n, _, err := s.targetConn.ReadFromUDP(readBuf)
						if err != nil {
							mu.Lock()
							delete(sessions, s.clientAddr.String())
							fm.connManager.Remove(s.connID)
							mu.Unlock()
							return
						}
						_, err = conn.WriteToUDP(readBuf[:n], s.clientAddr)
						if err != nil {
							return
						}
						mu.Lock()
						if _, ok := sessions[s.clientAddr.String()]; ok {
							sessions[s.clientAddr.String()].lastActivity = time.Now()
						}
						mu.Unlock()
					}
				}(session)
				log.Printf("[%s] 新UDP会话已创建: %s -> %s", rule.Name, clientAddr.String(), targetConn.RemoteAddr().String())
			}
			session.lastActivity = time.Now()
			mu.Unlock()

			if _, err := session.targetConn.Write(buf[:n]); err != nil {
				log.Printf("[%s] 写入UDP目标失败: %v", rule.Name, err)
			}
		}
	}()

	return true
}