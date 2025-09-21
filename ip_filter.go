// cnnlei/network/network-33ab537e85847c302b55c126d843f77b047a1244/ip_filter.go
package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

type IPList struct { networks []*net.IPNet }
type IPFilterManager struct {
	lists    map[string]*IPList
	mu       sync.RWMutex
	globalAC GlobalAccessControl
}

func NewIPFilterManager(configIPLists map[string][]string, globalAC GlobalAccessControl) *IPFilterManager {
	manager := &IPFilterManager{
		lists:    make(map[string]*IPList),
		globalAC: globalAC,
	}
	manager.UpdateLists(configIPLists)
	return manager
}

func (m *IPFilterManager) UpdateLists(configIPLists map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lists = make(map[string]*IPList)
	for name, cidrList := range configIPLists {
		networks := make([]*net.IPNet, 0, len(cidrList))
		for _, cidrStr := range cidrList {
			trimmedCidrStr := strings.TrimSpace(cidrStr)
			if trimmedCidrStr == "" { continue }
			_, network, err := net.ParseCIDR(trimmedCidrStr)
			if err != nil {
				ip := net.ParseIP(trimmedCidrStr)
				if ip != nil {
					var mask net.IPMask
					if ip.To4() != nil { mask = net.CIDRMask(32, 32) } else { mask = net.CIDRMask(128, 128) }
					network = &net.IPNet{IP: ip, Mask: mask}
				} else {
					log.Printf("[IPFilter] 无法解析IP/CIDR: '%s'", trimmedCidrStr)
					continue
				}
			}
			networks = append(networks, network)
		}
		m.lists[name] = &IPList{networks: networks}
	}
	log.Printf("[IPFilter] 所有IP名单已更新，共加载 %d 个名单。", len(m.lists))
}

func (m *IPFilterManager) UpdateGlobalAC(globalAC GlobalAccessControl) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalAC = globalAC
	log.Println("[IPFilter] 全局访问控制配置已更新。")
}

func (m *IPFilterManager) isInList(ip net.IP, listName string) bool {
	m.mu.RLock()
	ipList, ok := m.lists[listName]
	m.mu.RUnlock()

	if !ok {
		log.Printf("[IPFilter] 警告: 请求了一个不存在的IP名单 '%s'", listName)
		return false
	}
	for _, network := range ipList.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ** 核心逻辑修改 **
func (m *IPFilterManager) IsAllowed(ipStr string, ruleAC RuleAccessControl) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "无效的IP地址"
	}

	m.mu.RLock()
	globalAC := m.globalAC
	m.mu.RUnlock()

	// 根据不同的全局模式执行不同的逻辑
	switch globalAC.Mode {
	case "priority":
		// 模式1: 优先级模式
		if globalAC.WhitelistEnabled && globalAC.WhitelistListName != "" {
			if m.isInList(ip, globalAC.WhitelistListName) {
				return true, "全局白名单允许"
			}
		}
		if globalAC.BlacklistEnabled && globalAC.BlacklistListName != "" {
			if m.isInList(ip, globalAC.BlacklistListName) {
				return false, "全局黑名单拒绝"
			}
		}
	case "whitelist_only":
		// 模式2: 仅白名单模式
		if globalAC.WhitelistEnabled && globalAC.WhitelistListName != "" {
			if m.isInList(ip, globalAC.WhitelistListName) {
				return true, "全局白名单(仅白名单模式)允许"
			}
			return false, "全局白名单(仅白名单模式)拒绝"
		}
	case "blacklist_only":
		// 模式3: 仅黑名单模式
		if globalAC.BlacklistEnabled && globalAC.BlacklistListName != "" {
			if m.isInList(ip, globalAC.BlacklistListName) {
				return false, "全局黑名单(仅黑名单模式)拒绝"
			}
		}
	}

	// 如果全局规则未处理，则进入规则级检查
	if ruleAC.Mode != "" && ruleAC.Mode != "disabled" && ruleAC.ListName != "" {
		isMatch := m.isInList(ip, ruleAC.ListName)
		if ruleAC.Mode == "whitelist" {
			return isMatch, "规则白名单"
		}
		if ruleAC.Mode == "blacklist" {
			return !isMatch, "规则黑名单"
		}
	}

	// 默认放行
	return true, "默认放行"
}