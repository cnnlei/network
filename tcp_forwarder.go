// cnnlei/network/network-33ab537e85847c302b55c126d843f77b047a1244/tcp_forwarder.go
package main

import (
	"io"
	"log"
	"net"
	"strings"
)

func handleTCPConnection(clientConn net.Conn, rule Rule, manager *ConnectionManager, ipFilterManager *IPFilterManager) {
	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]

	// 统一调用新的检查函数
	allowed, reason := ipFilterManager.IsAllowed(clientIP, rule.AccessControl)
	if !allowed {
		log.Printf("[%s] 已拒绝来自 %s 的连接: %s", rule.Name, clientIP, reason)
		clientConn.Close()
		return
	}
	
	connID := manager.Add("TCP", rule.Name, clientConn, nil)
	manager.Broadcast()
	
	defer func() {
		manager.Remove(connID)
		manager.Broadcast()
		log.Printf("[%s] TCP 连接已关闭: %s (ID: %d)", rule.Name, clientConn.RemoteAddr(), connID)
	}()
	defer clientConn.Close()

	targetConn, err := net.Dial("tcp", rule.ForwardAddress())
	if err != nil {
		log.Printf("[%s] 无法连接到TCP目标 %s: %v", rule.Name, rule.ForwardAddress(), err)
		return
	}
	defer targetConn.Close()

	manager.UpdateTargetConn(connID, targetConn)
	manager.Broadcast()
	log.Printf("[%s] TCP 连接已建立: %s <-> %s", rule.Name, clientConn.RemoteAddr(), targetConn.RemoteAddr())

	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

func startTCPForwarder(rule Rule, manager *ConnectionManager, ipFilterManager *IPFilterManager) {
	listener, err := net.Listen(rule.Protocol, rule.ListenAddress())
	if err != nil {
		log.Printf("错误: 无法为规则 [%s] 监听TCP端口 %s (%s): %v", rule.Name, rule.ListenAddress(), rule.Protocol, err)
		return
	}
	defer listener.Close()
	log.Printf("==== 规则 [%s] 已启动并成功监听TCP在 %s (%s) ====", rule.Name, rule.ListenAddress(), rule.Protocol)
	for {
		clientConn, err := listener.Accept()
		if err != nil { continue }
		go handleTCPConnection(clientConn, rule, manager, ipFilterManager)
	}
}