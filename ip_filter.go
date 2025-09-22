package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

type IPList struct {
	networks []*net.IPNet
}

type IPFilterManager struct {
	lists    map[string]*IPList
	mu       sync.RWMutex
	globalAC GlobalAccessControl
}

func parseCIDRList(cidrList []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrList))
	for _, cidrStr := range cidrList {
		trimmedCidrStr := strings.TrimSpace(cidrStr)
		if trimmedCidrStr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(trimmedCidrStr)
		if err != nil {
			ip := net.ParseIP(trimmedCidrStr)
			if ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				network = &net.IPNet{IP: ip, Mask: mask}
			} else {
				log.Printf("[IPFilter] 无法解析IP/CIDR: '%s' in list", trimmedCidrStr)
				continue
			}
		}
		networks = append(networks, network)
	}
	return networks
}

func NewIPFilterManager(config *Config) *IPFilterManager {
	manager := &IPFilterManager{
		lists:    make(map[string]*IPList),
		globalAC: config.GlobalAccessControl,
	}
	manager.UpdateAllManualLists(config.IPLists)
	return manager
}

func (m *IPFilterManager) UpdateAllManualLists(configIPLists IPLists) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for name, cidrList := range configIPLists.Whitelists {
		m.lists[name] = &IPList{networks: parseCIDRList(cidrList)}
	}
	for name, cidrList := range configIPLists.Blacklists {
		m.lists[name] = &IPList{networks: parseCIDRList(cidrList)}
	}
	for name, cidrList := range configIPLists.IPSets {
		m.lists[name] = &IPList{networks: parseCIDRList(cidrList)}
	}
	log.Println("[IPFilter] 所有手动IP名单已更新。")
}

func (m *IPFilterManager) UpdateDynamicList(name string, ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lists[name] = &IPList{networks: parseCIDRList(ips)}
}

func (m *IPFilterManager) RemoveList(name string) {
    m.mu.Lock()
    defer m.mu.Unlock()
    delete(m.lists, name)
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
		log.Printf("[IPFilter] 警告: 规则请求了一个不存在或尚未加载的IP名单 '%s'", listName)
		return false
	}

	for _, network := range ipList.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *IPFilterManager) IsAllowed(ipStr string, ruleAC RuleAccessControl) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "无效的IP地址"
	}

	m.mu.RLock()
	globalAC := m.globalAC
	m.mu.RUnlock()

	switch globalAC.Mode {
	case "priority":
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
		if globalAC.WhitelistEnabled && globalAC.WhitelistListName != "" {
			if m.isInList(ip, globalAC.WhitelistListName) {
				return true, "全局白名单(仅白名单模式)允许"
			}
			return false, "全局白名单(仅白名单模式)拒绝"
		}
	case "blacklist_only":
		if globalAC.BlacklistEnabled && globalAC.BlacklistListName != "" {
			if m.isInList(ip, globalAC.BlacklistListName) {
				return false, "全局黑名单(仅黑名单模式)拒绝"
			}
		}
	}

	if ruleAC.Mode != "" && ruleAC.Mode != "disabled" && ruleAC.ListName != "" {
		isMatch := m.isInList(ip, ruleAC.ListName)
		if ruleAC.Mode == "whitelist" {
			return isMatch, "规则白名单"
		}
		if ruleAC.Mode == "blacklist" {
			return !isMatch, "规则黑名单"
		}
	}

	return true, "默认放行"
}