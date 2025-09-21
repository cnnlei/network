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
type Rule struct {
	Name          string            `yaml:"name"`
	Protocol      string            `yaml:"protocol"`
	ListenPort    int               `yaml:"listen_port"`
	ForwardAddr   string            `yaml:"forward_addr"`
	ForwardPort   int               `yaml:"forward_port"`
	AccessControl RuleAccessControl `yaml:"access_control"`
}
type Config struct {
	IPLists map[string][]string `yaml:"ip_lists"`
	Rules   []Rule              `yaml:"rules"`
}

func (r Rule) ListenAddress() string { return fmt.Sprintf(":%d", r.ListenPort) }
func (r Rule) ForwardAddress() string { return fmt.Sprintf("%s:%d", r.ForwardAddr, r.ForwardPort) }
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil { return nil, err }
	return &config, nil
}