package main

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"
)

// WebManager 负责管理所有Web服务的生命周期
type WebManager struct {
	activeServices map[string]*http.Server
	mu             sync.Mutex
	ipFilter       *IPFilterManager
	connManager    *ConnectionManager
}

func NewWebManager(ipFilter *IPFilterManager, connManager *ConnectionManager) *WebManager {
	return &WebManager{
		activeServices: make(map[string]*http.Server),
		ipFilter:       ipFilter,
		connManager:    connManager,
	}
}

// StartRule 启动一个新的Web服务规则
func (m *WebManager) StartRule(rule WebServiceRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.activeServices[rule.Name]; exists {
		log.Printf("[WebManager] 规则 [%s] 已在运行中，无需重复启动。", rule.Name)
		return
	}

	if !rule.Enabled {
		log.Printf("[WebManager] 规则 [%s] 已被禁用，跳过启动。", rule.Name)
		return
	}

	// 创建一个新的WebForwarder
	forwarder, err := NewWebForwarder(rule, m.ipFilter, m.connManager)
	if err != nil {
		log.Printf("[WebManager] 创建规则 [%s] 失败: %v", rule.Name, err)
		return
	}

	// 启动HTTP服务
	server := forwarder.Start()
	m.activeServices[rule.Name] = server

	log.Printf("[WebManager] Web服务规则 [%s] 已在地址 [%s] 上启动。", rule.Name, server.Addr)
}

// StopRule 停止一个正在运行的Web服务规则
func (m *WebManager) StopRule(ruleName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	server, exists := m.activeServices[ruleName]
	if !exists {
		return
	}

	log.Printf("[WebManager] 正在停止Web服务规则 [%s]...", ruleName)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[WebManager] 停止规则 [%s] 时发生错误: %v", ruleName, err)
	} else {
		log.Printf("[WebManager] 规则 [%s] 已成功停止。", ruleName)
	}

	delete(m.activeServices, ruleName)
}

// RestartAll 根据最新的配置重启所有Web服务
func (m *WebManager) RestartAll(rules []WebServiceRule) {
	m.mu.Lock()
	// 停止所有当前服务
	for name := range m.activeServices {
		// 使用goroutine以避免在锁内长时间等待
		go m.StopRule(name)
	}
	m.activeServices = make(map[string]*http.Server)
	m.mu.Unlock()

	// 稍作等待，确保端口已释放
	time.Sleep(1 * time.Second)

	log.Println("[WebManager] 正在根据新配置重启所有Web服务...")
	for _, rule := range rules {
		m.StartRule(rule)
	}
}