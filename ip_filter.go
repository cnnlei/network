package main

import (
	"log"
	"net"
	"strings"
	"sync"
)

type IPList struct { networks []*net.IPNet }
type IPFilterManager struct {
	lists map[string]*IPList
	mu    sync.RWMutex
}

func NewIPFilterManager(configIPLists map[string][]string) *IPFilterManager {
	manager := &IPFilterManager{ lists: make(map[string]*IPList) }
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

func (m *IPFilterManager) IsAllowed(ipStr string, ruleAC RuleAccessControl) bool {
	if ruleAC.Mode == "" || ruleAC.Mode == "disabled" { return true }
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	m.mu.RLock()
	ipList, ok := m.lists[ruleAC.ListName]
	m.mu.RUnlock()
	if !ok {
		if ruleAC.Mode == "whitelist" { return false }
		return true
	}
	isMatch := false
	for _, network := range ipList.networks {
		if network.Contains(ip) {
			isMatch = true
			break
		}
	}
	if ruleAC.Mode == "whitelist" { return isMatch }
	if ruleAC.Mode == "blacklist" { return !isMatch }
	return true
}