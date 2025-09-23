package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

// --- Web服务规则的详细配置结构 ---

type WebSecurityConfig struct {
	BlockOn404Count   int `yaml:"block_on_404_count" json:"BlockOn404Count"`
	BlockOnBlockCount int `yaml:"block_on_block_count" json:"BlockOnBlockCount"`
}

type WebTLSConfig struct {
	Enabled        bool   `yaml:"enabled" json:"Enabled"`
	MinVersion     string `yaml:"min_version" json:"MinVersion"`
	HTTP3Enabled   bool   `yaml:"http3_enabled" json:"HTTP3Enabled"`
	ECHEnabled     bool   `yaml:"ech_enabled" json:"ECHEnabled"`
}

type WebRateLimitConfig struct {
	SendSpeedKBps    int `yaml:"send_speed_kbps" json:"SendSpeedKBps"`
	ReceiveSpeedKBps int `yaml:"receive_speed_kbps" json:"ReceiveSpeedKBps"`
}

type WebLimitsConfig struct {
	RuleRateLimit         WebRateLimitConfig `yaml:"rule_rate_limit" json:"RuleRateLimit"`
	ConnectionRateLimit   WebRateLimitConfig `yaml:"connection_rate_limit" json:"ConnectionRateLimit"`
	IPRateLimit           WebRateLimitConfig `yaml:"ip_rate_limit" json:"IPRateLimit"`
	IPConnectionLimit     int                `yaml:"ip_connection_limit" json:"IPConnectionLimit"`
}

type WebSubRuleSecurity struct {
	BlockOn404Count      int `yaml:"block_on_404_count" json:"BlockOn404Count"`
	BlockOnCorazaCount   int `yaml:"block_on_coraza_count" json:"BlockOnCorazaCount"`
}

type WebSubRuleBackend struct {
	Address               string `yaml:"address" json:"Address"`
	IgnoreTLSCert         bool   `yaml:"ignore_tls_cert" json:"IgnoreTLSCert"`
	UseTargetHostHeader   bool   `yaml:"use_target_host_header" json:"UseTargetHostHeader"`
	GrpcSecure            bool   `yaml:"grpc_secure" json:"GrpcSecure"`
	DisableKeepAlives     bool   `yaml:"disable_keep_alives" json:"DisableKeepAlives"`
}

type WebSubRuleNetwork struct {
	DisableConnectionReuse bool `yaml:"disable_connection_reuse" json:"DisableConnectionReuse"`
	NetworkType            string `yaml:"network_type" json:"NetworkType"`
	HttpClientTimeoutSec   int    `yaml:"http_client_timeout_sec" json:"HttpClientTimeoutSec"`
}

type WebSubRuleClientIP struct {
	FromHeader         bool   `yaml:"from_header" json:"FromHeader"`
	AddToHeader        bool   `yaml:"add_to_header" json:"AddToHeader"`
	AddToHeaderName    string `yaml:"add_to_header_name" json:"AddToHeaderName"`
	AddProtoToHeader   bool   `yaml:"add_proto_to_header" json:"AddProtoToHeader"`
	AddProtoToHeaderName string `yaml:"add_proto_to_header_name" json:"AddProtoToHeaderName"`
}

type WebSubRuleAuth struct {
	Enabled  bool   `yaml:"enabled" json:"Enabled"`
	Username string `yaml:"username" json:"Username"`
	Password string `yaml:"password" json:"Password"`
}

type WebSubRuleUserAgentFilter struct {
	Mode    string   `yaml:"mode" json:"Mode"`
	List    []string `yaml:"list" json:"List"`
}

type WebSubRule struct {
	Name            string                  `yaml:"name" json:"Name"`
	Enabled         bool                    `yaml:"enabled" json:"Enabled"`
	ServiceType     string                  `yaml:"service_type" json:"ServiceType"`
	FrontendAddress string                  `yaml:"frontend_address" json:"FrontendAddress"`
	Backend         WebSubRuleBackend       `yaml:"backend" json:"Backend"`
	RedirectURL     string                  `yaml:"redirect_url" json:"RedirectURL"`
	CorazaWAF       string                  `yaml:"coraza_waf" json:"CorazaWAF"`
	Security        WebSubRuleSecurity      `yaml:"security" json:"Security"`
	Network         WebSubRuleNetwork       `yaml:"network" json:"Network"`
	ClientIP        WebSubRuleClientIP      `yaml:"client_ip" json:"ClientIP"`
	CORSEnabled     bool                    `yaml:"cors_enabled" json:"CORSEnabled"`
	Auth            WebSubRuleAuth          `yaml:"auth" json:"Auth"`
	IPFilter        RuleAccessControl       `yaml:"ip_filter" json:"IPFilter"` // **MODIFIED**: Added IPFilter
	UserAgentFilter WebSubRuleUserAgentFilter `yaml:"user_agent_filter" json:"UserAgentFilter"`
	CustomRobotTxt  string                  `yaml:"custom_robot_txt" json:"CustomRobotTxt"`
	ForceHTTPS      bool                    `yaml:"force_https" json:"ForceHTTPS"`
	// **MODIFIED**: Removed OperationMode and Tag
}


type WebServiceRule struct {
	Name           string            `yaml:"name" json:"Name"`
	Enabled        bool              `yaml:"enabled" json:"Enabled"`
	ListenIPv4     bool              `yaml:"listen_ipv4" json:"ListenIPv4"`
	ListenIPv6     bool              `yaml:"listen_ipv6" json:"ListenIPv6"`
	ListenAddr     string            `yaml:"listen_addr" json:"ListenAddr"`
	ListenPort     int               `yaml:"listen_port" json:"ListenPort"`
	AccessControl  RuleAccessControl `yaml:"access_control" json:"AccessControl"`
	Security       WebSecurityConfig `yaml:"security" json:"Security"`
	TLS            WebTLSConfig      `yaml:"tls" json:"TLS"`
	ApplyToSubRules bool             `yaml:"apply_to_sub_rules" json:"ApplyToSubRules"`
	Limits         WebLimitsConfig   `yaml:"limits" json:"Limits"`
	SubRules       []WebSubRule      `yaml:"sub_rules" json:"SubRules"`
}

type LogCleanupByTime struct {
	Enabled bool   `yaml:"enabled" json:"Enabled"`
	Mode    string `yaml:"mode" json:"Mode"`
	Value   int    `yaml:"value" json:"Value"`
}
type LogCleanupByLines struct {
	Enabled     bool `yaml:"enabled" json:"Enabled"`
	RetainLines int  `yaml:"retain_lines" json:"RetainLines"`
}
type LogCleanupByRule struct {
	Enabled     bool `yaml:"enabled" json:"Enabled"`
	RetainLines int  `yaml:"retain_lines" json:"RetainLines"`
}
type LogSettings struct {
	CleanupByTime   LogCleanupByTime            `yaml:"cleanup_by_time" json:"CleanupByTime"`
	CleanupByLines  LogCleanupByLines           `yaml:"cleanup_by_lines" json:"CleanupByLines"`
	CleanupByRule   map[string]LogCleanupByRule `yaml:"cleanup_by_rule" json:"CleanupByRule"`
}
type AppSettings struct {
	LogDirectory    string      `yaml:"log_directory" json:"LogDirectory"`
	IPListDirectory string      `yaml:"ip_list_directory" json:"IPListDirectory"`
	Log             LogSettings `yaml:"log" json:"Log"`
}
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
	WebServices         []WebServiceRule    `yaml:"web_services" json:"web_services"`
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
    
    if config.Settings.LogDirectory == "" { config.Settings.LogDirectory = "." }
    if config.Settings.IPListDirectory == "" { config.Settings.IPListDirectory = "./ip_lists" }
	if config.Settings.Log.CleanupByTime.Mode == "" { config.Settings.Log.CleanupByTime.Mode = "days"; config.Settings.Log.CleanupByTime.Value = 7 }
	if config.Settings.Log.CleanupByLines.RetainLines == 0 { config.Settings.Log.CleanupByLines.RetainLines = 10000 }
	if config.Settings.Log.CleanupByRule == nil { config.Settings.Log.CleanupByRule = make(map[string]LogCleanupByRule) }

	if config.IPLists.Whitelists == nil { config.IPLists.Whitelists = make(map[string][]string) }
	if config.IPLists.Blacklists == nil { config.IPLists.Blacklists = make(map[string][]string) }
	if config.IPLists.IPSets == nil { config.IPLists.IPSets = make(map[string][]string) }
	if config.IPLists.CountryIPLists == nil { config.IPLists.CountryIPLists = make(map[string]*IPListConfig) }
	if config.IPLists.UrlIpSets == nil { config.IPLists.UrlIpSets = make(map[string]*IPListConfig) }
    if config.WebServices == nil {
        config.WebServices = make([]WebServiceRule, 0)
    }

	return &config, nil
}