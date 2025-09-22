package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

// LogCleanupByTime 定义了按时间自动清理的策略
type LogCleanupByTime struct {
	Enabled bool   `yaml:"enabled" json:"Enabled"`
	Mode    string `yaml:"mode" json:"Mode"` // "minutes", "hours", "days", "months"
	Value   int    `yaml:"value" json:"Value"`
}

// LogCleanupByLines 定义了按总条数自动清理的策略
type LogCleanupByLines struct {
	Enabled     bool `yaml:"enabled" json:"Enabled"`
	RetainLines int  `yaml:"retain_lines" json:"RetainLines"`
}

// LogCleanupByRule 定义了按规则条数自动清理的策略
type LogCleanupByRule struct {
	Enabled     bool `yaml:"enabled" json:"Enabled"`
	RetainLines int  `yaml:"retain_lines" json:"RetainLines"`
}

// LogSettings 包含日志清理的配置
type LogSettings struct {
	CleanupByTime   LogCleanupByTime            `yaml:"cleanup_by_time" json:"CleanupByTime"`
	CleanupByLines  LogCleanupByLines           `yaml:"cleanup_by_lines" json:"CleanupByLines"`
	CleanupByRule   map[string]LogCleanupByRule `yaml:"cleanup_by_rule" json:"CleanupByRule"`
}

// AppSettings 包含应用程序级别的设置
type AppSettings struct {
	LogDirectory    string      `yaml:"log_directory" json:"LogDirectory"`
	IPListDirectory string      `yaml:"ip_list_directory" json:"IPListDirectory"`
	Log             LogSettings `yaml:"log" json:"Log"`
}

// IPListConfig, RuleAccessControl, GlobalAccessControl, IPLists, Rule structs remain the same...
type IPListConfig struct {
	Type   string `yaml:"type" json:"Type"`
	Source string `yaml:"source,omitempty" json:"Source"`
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

type IPLists struct {
	Whitelists     map[string][]string      `yaml:"whitelists" json:"whitelists"`
	Blacklists     map[string][]string      `yaml:"blacklists" json:"blacklists"`
	IPSets         map[string][]string      `yaml:"ip_sets" json:"ip_sets"`
	CountryIPLists map[string]*IPListConfig `yaml:"country_ip_lists" json:"country_ip_lists"`
	UrlIpSets      map[string]*IPListConfig `yaml:"url_ip_sets" json:"url_ip_sets"`
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
	Settings            AppSettings         `yaml:"settings" json:"settings"`
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
    
    // 为Settings设置默认值
    if config.Settings.LogDirectory == "" {
        config.Settings.LogDirectory = "."
    }
    if config.Settings.IPListDirectory == "" {
        config.Settings.IPListDirectory = "./ip_lists"
    }
	if config.Settings.Log.CleanupByTime.Mode == "" {
		config.Settings.Log.CleanupByTime.Mode = "days"
		config.Settings.Log.CleanupByTime.Value = 7
	}
	if config.Settings.Log.CleanupByLines.RetainLines == 0 {
		config.Settings.Log.CleanupByLines.RetainLines = 10000
	}
	if config.Settings.Log.CleanupByRule == nil {
		config.Settings.Log.CleanupByRule = make(map[string]LogCleanupByRule)
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
	if config.IPLists.UrlIpSets == nil {
		config.IPLists.UrlIpSets = make(map[string]*IPListConfig)
	}

	return &config, nil
}