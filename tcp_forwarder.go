package main

import (
	"io"
	"log"
	"net"
	"strings"
)

// handleTCPConnection 处理单个TCP连接的转发
// 注意：startTCPForwarder函数已经被移到forwarder_manager.go中
func handleTCPConnection(clientConn net.Conn, rule Rule, manager *ConnectionManager, ipFilterManager *IPFilterManager) {
	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]

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