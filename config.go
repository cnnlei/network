// cnnlei/network/network-33ab537e85847c302b55c126d843f77b047a1244/config.go
package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type RuleAccessControl struct {
	Mode     string `yaml:"mode"`
	ListName string `yaml:"list_name"`
}

// 修改: 使用一个结构体来管理所有全局设置
type GlobalAccessControl struct {
	Mode              string `yaml:"mode"` // "priority", "whitelist_only", "blacklist_only"
	WhitelistEnabled  bool   `yaml:"whitelist_enabled"`
	WhitelistListName string `yaml:"whitelist_list_name"`
	BlacklistEnabled  bool   `yaml:"blacklist_enabled"`
	BlacklistListName string `yaml:"blacklist_list_name"`
}

type Rule struct {
	Name          string            `yaml:"name"`
	Protocol      string            `yaml:"protocol"`
	ListenAddr    string            `yaml:"listen_addr"`
	ListenPort    int               `yaml:"listen_port"`
	ForwardAddr   string            `yaml:"forward_addr"`
	ForwardPort   int               `yaml:"forward_port"`
	AccessControl RuleAccessControl `yaml:"access_control"`
	Enabled       bool              `yaml:"enabled"`
}

type Config struct {
	GlobalAccessControl GlobalAccessControl   `yaml:"global_access_control"` // 使用新的单一结构
	IPLists             map[string][]string `yaml:"ip_lists"`
	Rules               []Rule              `yaml:"rules"`
}

func (r Rule) ListenAddress() string {
	addr := r.ListenAddr
	if addr == "::" {
		addr = "[::]"
	}
	return fmt.Sprintf("%s:%d", addr, r.ListenPort)
}

func (r Rule) ForwardAddress() string { return fmt.Sprintf("%s:%d", r.ForwardAddr, r.ForwardPort) }

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil { return nil, err }
	return &config, nil
}