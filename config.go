package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

// IPListConfig 仅用于国家/URL IP列表
type IPListConfig struct {
	Type           string   `yaml:"type" json:"Type"`
	Source         string   `yaml:"source,omitempty" json:"Source"`
	UpdateInterval int      `yaml:"update_interval,omitempty" json:"UpdateInterval"`
}

type RuleAccessControl struct {
	Mode     string `yaml:"mode" json:"Mode"`
	ListName string `yaml:"list_name" json:"ListName"`
}

type GlobalAccessControl struct {
	Mode              string `yaml:"mode" json:"Mode"`
	WhitelistEnabled  bool   `yaml:"whitelist_enabled" json:"WhitelistEnabled"`
	WhitelistListName string `yaml:"whitelist_list_name" json:"WhitelistListName"`
	BlacklistEnabled  bool   `yaml:"blacklist_enabled" json:"BlacklistEnabled"`
	BlacklistListName string `yaml:"blacklist_list_name" json:"BlacklistListName"`
}

// IPLists 结构体恢复为四分类管理
type IPLists struct {
	Whitelists     map[string][]string      `yaml:"whitelists" json:"whitelists"`
	Blacklists     map[string][]string      `yaml:"blacklists" json:"blacklists"`
	IPSets         map[string][]string      `yaml:"ip_sets" json:"ip_sets"`
	CountryIPLists map[string]*IPListConfig `yaml:"country_ip_lists" json:"country_ip_lists"`
}

type Rule struct {
	Name          string            `yaml:"name" json:"Name"`
	Protocol      string            `yaml:"protocol" json:"Protocol"`
	ListenAddr    string            `yaml:"listen_addr" json:"ListenAddr"`
	ListenPort    int               `yaml:"listen_port" json:"ListenPort"`
	ForwardAddr   string            `yaml:"forward_addr" json:"ForwardAddr"`
	ForwardPort   int               `yaml:"forward_port" json:"ForwardPort"`
	AccessControl RuleAccessControl `yaml:"access_control" json:"AccessControl"`
	Enabled       bool              `yaml:"enabled" json:"Enabled"`
	RateLimit           int `yaml:"rate_limit,omitempty" json:"RateLimit"`
	ConnectionLimit     int `yaml:"connection_limit,omitempty" json:"ConnectionLimit"`
	UDPSessionTimeout   int `yaml:"udp_session_timeout,omitempty" json:"UDPSessionTimeout"`
	UDPMaxSessions      int `yaml:"udp_max_sessions,omitempty" json:"UDPMaxSessions"`
	UDPMaxBlockLength   int `yaml:"udp_max_block_length,omitempty" json:"UDPMaxBlockLength"`
}

type Config struct {
	GlobalAccessControl GlobalAccessControl `yaml:"global_access_control" json:"global_access_control"`
	IPLists             IPLists             `yaml:"ip_lists" json:"ip_lists"`
	Rules               []Rule              `yaml:"rules" json:"rules"`
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
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	if config.IPLists.Whitelists == nil {
		config.IPLists.Whitelists = make(map[string][]string)
	}
	if config.IPLists.Blacklists == nil {
		config.IPLists.Blacklists = make(map[string][]string)
	}
	if config.IPLists.IPSets == nil {
		config.IPLists.IPSets = make(map[string][]string)
	}
	if config.IPLists.CountryIPLists == nil {
		config.IPLists.CountryIPLists = make(map[string]*IPListConfig)
	}

	return &config, nil
}