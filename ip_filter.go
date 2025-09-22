package main

import (
	"bufio"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ManagedIPList 存储解析后的IP网络以及相关的元数据
type ManagedIPList struct {
	networks    []*net.IPNet
	LastUpdated time.Time
	Count       int
}

type IPFilterManager struct {
	lists    map[string]*ManagedIPList
	mu       sync.RWMutex
	globalAC GlobalAccessControl
}

// --- 辅助函数 ---
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func ipRangeToCIDRs(startIP, endIP net.IP) ([]*net.IPNet, error) {
	var cidrs []*net.IPNet
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)

	for end >= start {
		var maxsize uint32 = 32
		for maxsize > 0 {
			mask := uint32(^(big.NewInt(0).Lsh(big.NewInt(1), uint(32-maxsize+1)).Uint64() - 1))
			if (start&mask) != start || (start|(^mask)) > end {
				break
			}
			maxsize--
		}
		size := 32 - maxsize
		mask := net.CIDRMask(int(size), 32)
		cidrs = append(cidrs, &net.IPNet{IP: uint32ToIP(start), Mask: mask})
		start += (1 << (32 - size))
	}
	return cidrs, nil
}


func parseCIDRList(cidrList []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrList))
	for _, cidrStr := range cidrList {
		trimmedCidrStr := strings.TrimSpace(cidrStr)
		if trimmedCidrStr == "" {
			continue
		}

		if strings.Contains(trimmedCidrStr, " ") {
			parts := strings.Fields(trimmedCidrStr)
			if len(parts) == 2 {
				startIP := net.ParseIP(parts[0])
				endIP := net.ParseIP(parts[1])
				if startIP != nil && endIP != nil {
					rangeCIDRs, err := ipRangeToCIDRs(startIP, endIP)
					if err == nil {
						networks = append(networks, rangeCIDRs...)
						continue
					}
				}
			}
			log.Printf("[IPFilter] 无法解析IP范围: '%s'", trimmedCidrStr)
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
		lists:    make(map[string]*ManagedIPList),
		globalAC: config.GlobalAccessControl,
	}
	manager.UpdateAllManualLists(config.IPLists)
	for name := range config.IPLists.CountryIPLists {
		manager.UpdateDynamicListFromFile(name)
	}
	for name := range config.IPLists.UrlIpSets {
		manager.UpdateDynamicListFromFile(name)
	}
	return manager
}

func (m *IPFilterManager) UpdateAllManualLists(configIPLists IPLists) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	update := func(name string, cidrList []string) {
		networks := parseCIDRList(cidrList)
		m.lists[name] = &ManagedIPList{
			networks:    networks,
			Count:       len(networks),
			LastUpdated: time.Now(),
		}
	}

	for name, cidrList := range configIPLists.Whitelists {
		update(name, cidrList)
	}
	for name, cidrList := range configIPLists.Blacklists {
		update(name, cidrList)
	}
	for name, cidrList := range configIPLists.IPSets {
		update(name, cidrList)
	}
	log.Println("[IPFilter] 所有手动IP名单已更新。")
}

func (m *IPFilterManager) UpdateDynamicList(name string, ips []string, updatedTime time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	networks := parseCIDRList(ips)
	m.lists[name] = &ManagedIPList{
		networks:    networks,
		Count:       len(ips),
		LastUpdated: updatedTime,
	}
}

func (m *IPFilterManager) UpdateDynamicListFromFile(name string) {
	configMutex.RLock()
	filePath := filepath.Join(currentConfig.Settings.IPListDirectory, name+".txt")
	configMutex.RUnlock()

    file, err := os.Open(filePath)
    if err != nil {
        return
    }
    defer file.Close()

    var ips []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        ips = append(ips, scanner.Text())
    }

    fileInfo, err := file.Stat()
    updateTime := time.Now()
    if err == nil {
        updateTime = fileInfo.ModTime()
    }

    m.UpdateDynamicList(name, ips, updateTime)
    log.Printf("[IPFilter] 已从缓存文件加载名单 [%s] 到内存。", name)
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
	managedList, ok := m.lists[listName]
	m.mu.RUnlock()

	if !ok {
		log.Printf("[IPFilter] 警告: 规则请求了一个不存在或尚未加载的IP名单 '%s'", listName)
		return false
	}

	for _, network := range managedList.networks {
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