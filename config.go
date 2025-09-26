package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ManualCertificate represents a single manually configured certificate.
type ManualCertificate struct {
	Domains  []string `yaml:"domains" json:"Domains"`
	CertPath string   `yaml:"cert_path" json:"CertPath"`
	KeyPath  string   `yaml:"key_path" json:"KeyPath"`
}

// CloudflareConfig holds Cloudflare API credentials.
type CloudflareConfig struct {
	Email    string `yaml:"email" json:"Email"`
	APIKey   string `yaml:"api_key" json:"APIKey"`
	APIToken string `yaml:"api_token" json:"APIToken"`
}

// ACMEAccount defines a single ACME account and the domains it manages.
type ACMEAccount struct {
	Name       string           `yaml:"name" json:"Name"`
	Provider   string           `yaml:"provider" json:"Provider"`
	Email      string           `yaml:"email" json:"Email"`
	Cloudflare CloudflareConfig `yaml:"cloudflare" json:"Cloudflare"`
	Domains    []string         `yaml:"domains" json:"Domains"`
}

// ACMETLSConfig contains all ACME related configurations.
type ACMETLSConfig struct {
	Enabled  bool          `yaml:"enabled" json:"Enabled"`
	Accounts []ACMEAccount `yaml:"accounts" json:"Accounts"`
}

// TLSConfig defines the global TLS settings, now supporting both manual and ACME.
type TLSConfig struct {
	Enabled       bool                `yaml:"enabled" json:"Enabled"`
	CertDirectory string              `yaml:"cert_directory" json:"CertDirectory"`
	Manual        []ManualCertificate `yaml:"manual" json:"Manual"`
	ACME          ACMETLSConfig       `yaml:"acme" json:"ACME"`
}

// WebSecurityConfig ...
type WebSecurityConfig struct {
	BlockOn404Count   int `yaml:"block_on_404_count" json:"BlockOn404Count"`
	BlockOnBlockCount int `yaml:"block_on_block_count" json:"BlockOnBlockCount"`
}

// WebTLSConfig ...
type WebTLSConfig struct {
	Enabled      bool   `yaml:"enabled" json:"Enabled"`
	MinVersion   string `yaml:"min_version" json:"MinVersion"`
	HTTP3Enabled bool   `yaml:"http3_enabled" json:"HTTP3Enabled"`
	ECHEnabled   bool   `yaml:"ech_enabled" json:"ECHEnabled"`
}

// WebRateLimitConfig ...
type WebRateLimitConfig struct {
	SendSpeedKBps    int `yaml:"send_speed_kbps" json:"SendSpeedKBps"`
	ReceiveSpeedKBps int `yaml:"receive_speed_kbps" json:"ReceiveSpeedKBps"`
}

// WebLimitsConfig ...
type WebLimitsConfig struct {
	RuleRateLimit       WebRateLimitConfig `yaml:"rule_rate_limit" json:"RuleRateLimit"`
	ConnectionRateLimit WebRateLimitConfig `yaml:"connection_rate_limit" json:"ConnectionRateLimit"`
	IPRateLimit         WebRateLimitConfig `yaml:"ip_rate_limit" json:"IPRateLimit"`
	IPConnectionLimit   int                `yaml:"ip_connection_limit" json:"IPConnectionLimit"`
}

// WebSubRuleSecurity ...
type WebSubRuleSecurity struct {
	BlockOn404Count    int `yaml:"block_on_404_count" json:"BlockOn404Count"`
	BlockOnCorazaCount int `yaml:"block_on_coraza_count" json:"BlockOnCorazaCount"`
}

// WebSubRuleBackend ...
type WebSubRuleBackend struct {
	Address             string `yaml:"address" json:"Address"`
	IgnoreTLSCert       bool   `yaml:"ignore_tls_cert" json:"IgnoreTLSCert"`
	UseTargetHostHeader bool   `yaml:"use_target_host_header" json:"UseTargetHostHeader"`
	GrpcSecure          bool   `yaml:"grpc_secure" json:"GrpcSecure"`
	DisableKeepAlives   bool   `yaml:"disable_keep_alives" json:"DisableKeepAlives"`
}

// WebSubRuleNetwork ...
type WebSubRuleNetwork struct {
	DisableConnectionReuse bool   `yaml:"disable_connection_reuse" json:"DisableConnectionReuse"`
	NetworkType            string `yaml:"network_type" json:"NetworkType"`
	HttpClientTimeoutSec   int    `yaml:"http_client_timeout_sec" json:"HttpClientTimeoutSec"`
}

// WebSubRuleClientIP ...
type WebSubRuleClientIP struct {
	FromHeader           bool   `yaml:"from_header" json:"FromHeader"`
	FromHeaderName       string `yaml:"from_header_name" json:"FromHeaderName"`
	AddToHeader          bool   `yaml:"add_to_header" json:"AddToHeader"`
	AddToHeaderName      string `yaml:"add_to_header_name" json:"AddToHeaderName"`
	AddProtoToHeader     bool   `yaml:"add_proto_to_header" json:"AddProtoToHeader"`
	AddProtoToHeaderName string `yaml:"add_proto_to_header_name" json:"AddProtoToHeaderName"`
	AddHostToHeader      bool   `yaml:"add_host_to_header" json:"AddHostToHeader"`
	AddHostToHeaderName  string `yaml:"add_host_to_header_name" json:"AddHostToHeaderName"`
}

// WebSubRuleAuth ...
type WebSubRuleAuth struct {
	Enabled  bool   `yaml:"enabled" json:"Enabled"`
	Username string `yaml:"username" json:"Username"`
	Password string `yaml:"password" json:"Password"`
}

// WebSubRuleUserAgentFilter ...
type WebSubRuleUserAgentFilter struct {
	Mode string   `yaml:"mode" json:"Mode"`
	List []string `yaml:"list" json:"List"`
}

// WebSubRuleForwardedHeaders ...
type WebSubRuleForwardedHeaders struct {
	Enabled bool `yaml:"enabled" json:"Enabled"`
}

// WebSubRule ...
type WebSubRule struct {
	Name            string                    `yaml:"name" json:"Name"`
	Enabled         bool                      `yaml:"enabled" json:"Enabled"`
	ServiceType     string                    `yaml:"service_type" json:"ServiceType"`
	FrontendAddress string                    `yaml:"frontend_address" json:"FrontendAddress"`
	Backend         WebSubRuleBackend         `yaml:"backend" json:"Backend"`
	RedirectURL     string                    `yaml:"redirect_url" json:"RedirectURL"`
	CorazaWAF       string                    `yaml:"coraza_waf" json:"CorazaWAF"`
	Security        WebSubRuleSecurity        `yaml:"security" json:"Security"`
	Network         WebSubRuleNetwork         `yaml:"network" json:"Network"`
	ClientIP        WebSubRuleClientIP        `yaml:"client_ip" json:"ClientIP"`
	ForwardedHeaders WebSubRuleForwardedHeaders `yaml:"forwarded_headers" json:"ForwardedHeaders"`
	CORSEnabled     bool                      `yaml:"cors_enabled" json:"CORSEnabled"`
	Auth            WebSubRuleAuth            `yaml:"auth" json:"Auth"`
	IPFilter        RuleAccessControl         `yaml:"ip_filter" json:"IPFilter"`
	UserAgentFilter WebSubRuleUserAgentFilter `yaml:"user_agent_filter" json:"UserAgentFilter"`
	CustomRobotTxt  string                    `yaml:"custom_robot_txt" json:"CustomRobotTxt"`
	ForceHTTPS      bool                      `yaml:"force_https" json:"ForceHTTPS"`
	Limits          WebLimitsConfig           `yaml:"limits" json:"Limits"`
}

// WebUnmatchedRequestConfig ...
type WebUnmatchedRequestConfig struct {
	Action       string `yaml:"action" json:"Action"`
	ProxyAddress string `yaml:"proxy_address,omitempty" json:"ProxyAddress,omitempty"`
	RedirectURL  string `yaml:"redirect_url,omitempty" json:"RedirectURL,omitempty"`
	StaticText   string `yaml:"static_text,omitempty" json:"StaticText,omitempty"`
}

// WebServiceRule ...
type WebServiceRule struct {
	Name             string                    `yaml:"name" json:"Name"`
	Enabled          bool                      `yaml:"enabled" json:"Enabled"`
	ListenIPv4       bool                      `yaml:"listen_ipv4" json:"ListenIPv4"`
	ListenIPv6       bool                      `yaml:"listen_ipv6" json:"ListenIPv6"`
	ListenAddr       string                    `yaml:"listen_addr" json:"ListenAddr"`
	ListenPort       int                       `yaml:"listen_port" json:"ListenPort"`
	AccessControl    RuleAccessControl         `yaml:"access_control" json:"AccessControl"`
	Security         WebSecurityConfig         `yaml:"security" json:"Security"`
	TLS              WebTLSConfig              `yaml:"tls" json:"TLS"`
	ApplyToSubRules  bool                      `yaml:"apply_to_sub_rules" json:"ApplyToSubRules"`
	Limits           WebLimitsConfig           `yaml:"limits" json:"Limits"`
	UnmatchedRequest WebUnmatchedRequestConfig `yaml:"unmatched_request" json:"UnmatchedRequest"`
	SubRules         []WebSubRule              `yaml:"sub_rules" json:"SubRules"`
}

// LogCleanupByTime ...
type LogCleanupByTime struct {
	Enabled bool   `yaml:"enabled" json:"Enabled"`
	Mode    string `yaml:"mode" json:"Mode"`
	Value   int    `yaml:"value" json:"Value"`
}

// LogCleanupByLines ...
type LogCleanupByLines struct {
	Enabled     bool `yaml:"enabled" json:"Enabled"`
	RetainLines int  `yaml:"retain_lines" json:"RetainLines"`
}

// LogCleanupByRule ...
type LogCleanupByRule struct {
	Enabled     bool `yaml:"enabled" json:"Enabled"`
	RetainLines int  `yaml:"retain_lines" json:"RetainLines"`
}

// LogSettings ...
type LogSettings struct {
	CleanupByTime  LogCleanupByTime            `yaml:"cleanup_by_time" json:"CleanupByTime"`
	CleanupByLines LogCleanupByLines           `yaml:"cleanup_by_lines" json:"CleanupByLines"`
	CleanupByRule  map[string]LogCleanupByRule `yaml:"cleanup_by_rule" json:"CleanupByRule"`
}

// AppSettings ...
type AppSettings struct {
	LogDirectory    string      `yaml:"log_directory" json:"LogDirectory"`
	IPListDirectory string      `yaml:"ip_list_directory" json:"IPListDirectory"`
	Log             LogSettings `yaml:"log" json:"Log"`
}

// IPListConfig ...
type IPListConfig struct {
	Type   string `yaml:"type" json:"Type"`
	Source string `yaml:"source,omitempty" json:"Source"`
}

// RuleAccessControl ...
type RuleAccessControl struct {
	Mode     string `yaml:"mode" json:"Mode"`
	ListName string `yaml:"list_name" json:"ListName"`
}

// GlobalAccessControl ...
type GlobalAccessControl struct {
	Mode              string `yaml:"mode" json:"Mode"`
	WhitelistEnabled  bool   `yaml:"whitelist_enabled" json:"WhitelistEnabled"`
	WhitelistListName string `yaml:"whitelist_list_name" json:"WhitelistListName"`
	BlacklistEnabled  bool   `yaml:"blacklist_enabled" json:"BlacklistEnabled"`
	BlacklistListName string `yaml:"blacklist_list_name" json:"BlacklistListName"`
}

// IPLists ...
type IPLists struct {
	Whitelists     map[string][]string      `yaml:"whitelists" json:"whitelists"`
	Blacklists     map[string][]string      `yaml:"blacklists" json:"blacklists"`
	IPSets         map[string][]string      `yaml:"ip_sets" json:"ip_sets"`
	CountryIPLists map[string]*IPListConfig `yaml:"country_ip_lists" json:"country_ip_lists"`
	UrlIpSets      map[string]*IPListConfig `yaml:"url_ip_sets" json:"url_ip_sets"`
}

// Rule ...
type Rule struct {
	Name              string            `yaml:"name" json:"Name"`
	Protocol          string            `yaml:"protocol" json:"Protocol"`
	ListenAddr        string            `yaml:"listen_addr" json:"ListenAddr"`
	ListenPort        int               `yaml:"listen_port" json:"ListenPort"`
	ForwardAddr       string            `yaml:"forward_addr" json:"ForwardAddr"`
	ForwardPort       int               `yaml:"forward_port" json:"ForwardPort"`
	AccessControl     RuleAccessControl `yaml:"access_control" json:"AccessControl"`
	Enabled           bool              `yaml:"enabled" json:"Enabled"`
	RateLimit         int               `yaml:"rate_limit,omitempty" json:"RateLimit"`
	ConnectionLimit   int               `yaml:"connection_limit,omitempty" json:"ConnectionLimit"`
	UDPSessionTimeout int               `yaml:"udp_session_timeout,omitempty" json:"UDPSessionTimeout"`
	UDPMaxSessions    int               `yaml:"udp_max_sessions,omitempty" json:"UDPMaxSessions"`
	UDPMaxBlockLength int               `yaml:"udp_max_block_length,omitempty" json:"UDPMaxBlockLength"`
}

// WAFRuleSet defines a named collection of WAF rules.
type WAFRuleSet struct {
	Name   string   `yaml:"name" json:"Name"`
	Source string   `yaml:"source" json:"Source"` // 'file' or 'url' or 'inline'
	Path   string   `yaml:"path" json:"Path"`     // File path or URL
	Rules  []string `yaml:"rules" json:"Rules"`   // Raw rules
}

// WAFConfig holds the WAF configuration.
type WAFConfig struct {
	Enabled       bool         `yaml:"enabled" json:"Enabled"`
	DefaultAction string       `yaml:"default_action" json:"DefaultAction"`
	RuleSets      []WAFRuleSet `yaml:"rule_sets" json:"RuleSets"`
  DefaultActionBody string       `yaml:"default_action_body" json:"DefaultActionBody"`
}

// Config is the main configuration struct
type Config struct {
	Settings            AppSettings         `yaml:"settings" json:"settings"`
	GlobalAccessControl GlobalAccessControl `yaml:"global_access_control" json:"global_access_control"`
	IPLists             IPLists             `yaml:"ip_lists" json:"ip_lists"`
	Rules               []Rule              `yaml:"rules" json:"rules"`
	WebServices         []WebServiceRule    `yaml:"web_services" json:"web_services"`
	TLS                 TLSConfig           `yaml:"tls" json:"tls"`
	WAF                 WAFConfig           `yaml:"waf" json:"waf"`
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
	if config.TLS.CertDirectory == "" {
		config.TLS.CertDirectory = "./certs"
	}
	if config.WebServices == nil {
		config.WebServices = make([]WebServiceRule, 0)
	}
	if config.TLS.Manual == nil {
		config.TLS.Manual = make([]ManualCertificate, 0)
	}
	if config.TLS.ACME.Accounts == nil {
		config.TLS.ACME.Accounts = make([]ACMEAccount, 0)
	}
	if config.WAF.RuleSets == nil {
		config.WAF.RuleSets = make([]WAFRuleSet, 0)
	}
	// Add default action if it is missing
	if config.WAF.DefaultAction == "" {
		config.WAF.DefaultAction = "phase:2,deny,status:403,log"
	}

	return &config, nil
}