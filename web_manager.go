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
	activeServices map[string][]*http.Server // A rule can have multiple servers
	ruleStatus     map[string]string       // **NEW**: Tracks the runtime status of each rule ("running", "stopped", "error")
	mu             sync.Mutex
	ipFilter       *IPFilterManager
	connManager    *ConnectionManager
}

func NewWebManager(ipFilter *IPFilterManager, connManager *ConnectionManager) *WebManager {
	return &WebManager{
		activeServices: make(map[string][]*http.Server),
		ruleStatus:     make(map[string]string),
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
		m.ruleStatus[rule.Name] = "stopped"
		return
	}

	forwarder, err := NewWebForwarder(rule, m.ipFilter, m.connManager)
	if err != nil {
		log.Printf("[WebManager] 创建规则 [%s] 失败: %v", rule.Name, err)
		m.ruleStatus[rule.Name] = "error"
		return
	}

	servers := forwarder.Start()
	// **FIX**: If no servers were successfully started, mark the rule as having an error.
	if len(servers) > 0 {
		m.activeServices[rule.Name] = servers
		m.ruleStatus[rule.Name] = "running"
	} else {
		log.Printf("[WebManager] 规则 [%s] 未能启动任何监听器，请检查日志。", rule.Name)
		m.ruleStatus[rule.Name] = "error"
	}
}

// StopRule 停止一个正在运行的Web服务规则
func (m *WebManager) StopRule(ruleName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	servers, exists := m.activeServices[ruleName]
	if !exists {
		// If it doesn't exist, it's already stopped.
		m.ruleStatus[ruleName] = "stopped"
		return
	}

	log.Printf("[WebManager] 正在停止Web服务规则 [%s]...", ruleName)
	for _, server := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("[WebManager] 停止规则 [%s] 的监听 [%s] 时发生错误: %v", ruleName, server.Addr, err)
		} else {
			log.Printf("[WebManager] 规则 [%s] 的监听 [%s] 已成功停止。", ruleName, server.Addr)
		}
	}

	delete(m.activeServices, ruleName)
	m.ruleStatus[ruleName] = "stopped"
}

// GetRuleStatuses returns the current runtime status of all configured web rules.
func (m *WebManager) GetRuleStatuses(rules []WebServiceRule) map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	statuses := make(map[string]string)
	for _, rule := range rules {
		if status, ok := m.ruleStatus[rule.Name]; ok {
			// If rule is disabled in config, it should always be "stopped"
			if !rule.Enabled {
				statuses[rule.Name] = "stopped"
			} else {
				statuses[rule.Name] = status
			}
		} else {
			// If we have no status, but it's enabled, it must have failed silently before. Mark as error.
			if rule.Enabled {
				statuses[rule.Name] = "error"
			} else {
				statuses[rule.Name] = "stopped"
			}
		}
	}
	return statuses
}


// RestartRule 平滑地重启一个规则，用于应用子规则等配置变更
func (m *WebManager) RestartRule(rule WebServiceRule) {
	m.StopRule(rule.Name)
	time.Sleep(200 * time.Millisecond)
	m.StartRule(rule)
}


// RestartAll 根据最新的配置重启所有Web服务
func (m *WebManager) RestartAll(rules []WebServiceRule) {
	m.mu.Lock()
	for name := range m.activeServices {
		go m.StopRule(name)
	}
	m.activeServices = make(map[string][]*http.Server)
	m.ruleStatus = make(map[string]string) // Reset statuses
	m.mu.Unlock()

	time.Sleep(1 * time.Second)

	log.Println("[WebManager] 正在根据新配置重启所有Web服务...")
	for _, rule := range rules {
		m.StartRule(rule)
	}
}