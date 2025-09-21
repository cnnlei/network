package main

import (
	"log"
	"net"
	"sync"
	"time"
)

const udpTimeout = 60 * time.Second

type udpSession struct {
	clientAddr   *net.UDPAddr
	targetConn   *net.UDPConn
	lastActivity time.Time
	connID       int64
}

func startUDPForwarder(rule Rule, manager *ConnectionManager, ipFilterManager *IPFilterManager) {
	listenAddr, err := net.ResolveUDPAddr("udp", rule.ListenAddress())
	if err != nil { log.Fatalf("致命错误: 无法解析UDP监听地址 [%s]: %v", rule.Name, err); return }
	
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil { log.Fatalf("致命错误: 无法为规则 [%s] 监听UDP端口 %s: %v", rule.Name, rule.ListenAddress(), err); return }
	defer conn.Close()
	log.Printf("==== 规则 [%s] 已启动并成功监听UDP在 %s ====", rule.Name, rule.ListenAddress())

	sessions := make(map[string]*udpSession)
	var mu sync.Mutex

	go func() {
		for {
			time.Sleep(30 * time.Second)
			mu.Lock()
			for key, session := range sessions {
				if time.Since(session.lastActivity) > udpTimeout {
					session.targetConn.Close()
					delete(sessions, key)
					manager.Remove(session.connID)
					manager.Broadcast()
					log.Printf("[%s] UDP会话已超时并清理: %s", rule.Name, key)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil { continue }

		clientIP := clientAddr.IP.String()
		if !ipFilterManager.IsAllowed(clientIP, rule.AccessControl) {
			log.Printf("[%s] 已拒绝来自 %s 的UDP数据包 (访问控制)", rule.Name, clientIP)
			continue
		}

		mu.Lock()
		session, found := sessions[clientAddr.String()]
		if !found {
			targetAddr, err := net.ResolveUDPAddr("udp", rule.ForwardAddress())
			if err != nil { log.Printf("[%s] 无法解析UDP目标地址: %v", rule.Name, err); mu.Unlock(); continue }
			
			targetConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil { log.Printf("[%s] 无法连接UDP目标: %v", rule.Name, err); mu.Unlock(); continue }
			
			connID := manager.Add("UDP", rule.Name, nil, targetConn)
			manager.connections[connID].ClientAddr = clientAddr.String()
			manager.Broadcast()

			session = &udpSession{
				clientAddr:   clientAddr,
				targetConn:   targetConn,
				lastActivity: time.Now(),
				connID:       connID,
			}
			sessions[clientAddr.String()] = session

			go func(s *udpSession) {
				buf := make([]byte, 65535)
				for {
					n, _, err := s.targetConn.ReadFromUDP(buf)
					if err != nil {
						mu.Lock()
						delete(sessions, s.clientAddr.String())
						manager.Remove(s.connID)
						manager.Broadcast()
						mu.Unlock()
						return
					}
					conn.WriteToUDP(buf[:n], s.clientAddr)
					mu.Lock()
					s.lastActivity = time.Now()
					mu.Unlock()
				}
			}(session)
			log.Printf("[%s] 新UDP会话已创建: %s -> %s", rule.Name, clientAddr.String(), targetConn.RemoteAddr().String())
		}
		session.lastActivity = time.Now()
		mu.Unlock()

		session.targetConn.Write(buf[:n])
	}
}