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
	mu                sync.Mutex
	activeListeners   map[string][]net.Listener
	activeUDPConns    map[string][]*net.UDPConn
	tcpConnectionCounts map[string]int
	connManager       *ConnectionManager
	ipFilterManager   *IPFilterManager
	cancelFuncs       map[string]context.CancelFunc
}

func NewForwarderManager(connManager *ConnectionManager, ipFilterManager *IPFilterManager) *ForwarderManager {
	return &ForwarderManager{
		activeListeners:   make(map[string][]net.Listener),
		activeUDPConns:    make(map[string][]*net.UDPConn),
		tcpConnectionCounts: make(map[string]int),
		connManager:       connManager,
		ipFilterManager:   ipFilterManager,
		cancelFuncs:       make(map[string]context.CancelFunc),
	}
}

func (fm *ForwarderManager) StartRule(rule Rule) {
	if !rule.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	fm.mu.Lock()
	fm.cancelFuncs[rule.Name] = cancel
	fm.tcpConnectionCounts[rule.Name] = 0 // Initialize connection count
	fm.mu.Unlock()

	proto := strings.ToLower(rule.Protocol)

	// ** BUG FIX **: Correctly handle "tcp,udp" protocol
	// Start a TCP forwarder if "tcp" is in the protocol string
	if strings.Contains(proto, "tcp") {
		tcpRule := rule
		// Create a specific protocol string for net.Listen (e.g., "tcp", "tcp4", "tcp6")
		if strings.Contains(proto, "tcp,") || strings.Contains(proto, ",tcp") || proto == "tcp" {
			tcpRule.Protocol = "tcp" 
		} else {
			tcpRule.Protocol = proto // Handles "tcp4", "tcp6" directly
		}
		go fm.startTCPForwarder(ctx, tcpRule)
	}
	
	// Start a UDP forwarder if "udp" is in the protocol string
	if strings.Contains(proto, "udp") {
		udpRule := rule
		// Create a specific protocol string for net.ListenUDP (e.g., "udp", "udp4", "udp6")
		if strings.Contains(proto, "udp,") || strings.Contains(proto, ",udp") || proto == "udp" {
			udpRule.Protocol = "udp"
		} else {
			udpRule.Protocol = proto // Handles "udp4", "udp6" directly
		}
		go fm.startUDPForwarder(ctx, udpRule)
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
}

func (fm *ForwarderManager) startTCPForwarder(ctx context.Context, rule Rule) {
	// Adjust protocol for IPv4/IPv6 binding if ListenAddr is set explicitly
	protocol := "tcp"
	if rule.ListenAddr == "0.0.0.0" {
		protocol = "tcp4"
	} else if rule.ListenAddr == "::" {
		protocol = "tcp6"
	}
	
	listener, err := net.Listen(protocol, rule.ListenAddress())
	if err != nil {
		log.Printf("错误: 无法为规则 [%s] 监听TCP端口 %s (%s): %v", rule.Name, rule.ListenAddress(), protocol, err)
		return
	}
	fm.mu.Lock()
	fm.activeListeners[rule.Name] = append(fm.activeListeners[rule.Name], listener)
	fm.mu.Unlock()
	log.Printf("==== 规则 [%s] 已启动并成功监听TCP在 %s (%s) ====", rule.Name, rule.ListenAddress(), protocol)
	
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	defer func() {
		fm.mu.Lock()
		delete(fm.activeListeners, rule.Name)
		fm.mu.Unlock()
		log.Printf("==== 规则 [%s] 的TCP监听已关闭 ====", rule.Name)
	}()

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
		fm.connManager.Broadcast()
		log.Printf("[%s] TCP 连接已关闭: %s (ID: %d)", rule.Name, clientConn.RemoteAddr(), connID)
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
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(limitedClientConn, targetConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()
	
	wg.Wait()
}


func (fm *ForwarderManager) startUDPForwarder(ctx context.Context, rule Rule) {
	protocol := "udp"
	if rule.ListenAddr == "0.0.0.0" {
		protocol = "udp4"
	} else if rule.ListenAddr == "::" {
		protocol = "udp6"
	}

	listenAddr, err := net.ResolveUDPAddr(protocol, rule.ListenAddress())
	if err != nil {
		log.Printf("错误: 无法解析UDP监听地址 [%s] (%s): %v", rule.Name, rule.ListenAddress(), protocol, err)
		return
	}
	conn, err := net.ListenUDP(protocol, listenAddr)
	if err != nil {
		log.Printf("错误: 无法为规则 [%s] 监听UDP端口 %s (%s): %v", rule.Name, rule.ListenAddress(), protocol, err)
		return
	}
	fm.mu.Lock()
	fm.activeUDPConns[rule.Name] = append(fm.activeUDPConns[rule.Name], conn)
	fm.mu.Unlock()
	log.Printf("==== 规则 [%s] 已启动并成功监听UDP在 %s (%s) ====", rule.Name, rule.ListenAddress(), protocol)
	
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	defer func() {
		fm.mu.Lock()
		delete(fm.activeUDPConns, rule.Name)
		fm.mu.Unlock()
		log.Printf("==== 规则 [%s] 的UDP监听已关闭 ====", rule.Name)
	}()

	sessions := make(map[string]*udpSession)
	var mu sync.Mutex

	timeout := time.Duration(rule.UDPSessionTimeout) * time.Millisecond
	if timeout == 0 {
		timeout = 30000 * time.Millisecond // Default
	}

	maxSessions := rule.UDPMaxSessions
	if maxSessions == 0 {
		maxSessions = 32 // Default
	}
	
	maxBlockLength := rule.UDPMaxBlockLength
	if maxBlockLength == 0 {
		maxBlockLength = 1500 // Default
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
						fm.connManager.Broadcast()
						log.Printf("[%s] UDP会话已超时并清理: %s", rule.Name, key)
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
						fm.connManager.Broadcast()
						mu.Unlock()
						return
					}
					_, err = conn.WriteToUDP(readBuf[:n], s.clientAddr)
					if err != nil {
						return
					}
					mu.Lock()
					s.lastActivity = time.Now()
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
}