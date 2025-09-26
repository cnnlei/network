package main

import (
	"bufio"
	"context"
	"flag"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

var (
	configMutex      = &sync.RWMutex{}
	currentConfig    *Config
	ipFilterManager  *IPFilterManager
	forwarderManager *ForwarderManager
	webManager       *WebManager
	updater          *Updater
	certManager      *CertManager
	wafManager       *WAFManager
	configPath       = flag.String("config", "config.yml", "Path to the main configuration file (config.yml)")
)

// --- 日志清理服务和相关结构 ---
type LogJanitor struct {
	stopChan chan struct{}
	ticker   *time.Ticker
}

type LogCleanupRequest struct {
	CleanupType string `json:"cleanupType"` // "time", "total_lines", "rule_lines", "all"
	Mode        string `json:"mode"`        // for "time"
	Value       int    `json:"value"`       // for "time", "total_lines"
	RuleName    string `json:"ruleName"`    // for "rule_lines"
	RetainLines int    `json:"retainLines"` // for "rule_lines"
}

func NewLogJanitor() *LogJanitor {
	return &LogJanitor{
		stopChan: make(chan struct{}),
	}
}

func (j *LogJanitor) Start() {
	log.Println("[LogJanitor] 日志清理服务已启动，每小时检查一次。")
	j.ticker = time.NewTicker(1 * time.Hour)
	go func() {
		for {
			select {
			case <-j.ticker.C:
				j.performAutoCleanup()
			case <-j.stopChan:
				j.ticker.Stop()
				return
			}
		}
	}()
}

func calculateCutoffTime(mode string, value int) time.Time {
	now := time.Now()
	switch mode {
	case "minutes":
		return now.Add(-time.Duration(value) * time.Minute)
	case "hours":
		return now.Add(-time.Duration(value) * time.Hour)
	case "days":
		return now.AddDate(0, 0, -value)
	case "months":
		return now.AddDate(0, -value, 0)
	default:
		return now
	}
}

func performCleanup(logPath string, req LogCleanupRequest) error {
	if req.CleanupType == "all" {
		log.Printf("[LogCleanup] 正在清理所有日志...")
		return os.Truncate(logPath, 0)
	}

	file, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		log.Printf("[LogCleanup] 清理时无法打开日志文件: %v", err)
		return err
	}

	var allLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}
	file.Close()

	var linesToKeep []string

	switch req.CleanupType {
	case "total_lines":
		retainCount := req.Value
		log.Printf("[LogCleanup] 开始清理日志，保留最新的 %d 条...", retainCount)
		if len(allLines) > retainCount {
			linesToKeep = allLines[len(allLines)-retainCount:]
		} else {
			linesToKeep = allLines
		}

	case "time":
		cutoffTime := calculateCutoffTime(req.Mode, req.Value)
		log.Printf("[LogCleanup] 开始清理 %v 之前的日志...", cutoffTime.Format("2006-01-02 15:04:05"))
		for _, line := range allLines {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				linesToKeep = append(linesToKeep, line)
				continue
			}
			dateTimeStr := parts[0] + " " + parts[1]
			logTime, err := time.Parse("2006/01/02 15:04:05", dateTimeStr)
			if err != nil {
				linesToKeep = append(linesToKeep, line)
				continue
			}
			if logTime.After(cutoffTime) {
				linesToKeep = append(linesToKeep, line)
			}
		}

	case "rule_lines":
		log.Printf("[LogCleanup] 开始为规则 [%s] 清理日志，保留最新的 %d 条...", req.RuleName, req.RetainLines)
		ruleLineIndices := []int{}
		re := regexp.MustCompile(`\[` + regexp.QuoteMeta(req.RuleName) + `\]`)
		for i, line := range allLines {
			if re.MatchString(line) {
				ruleLineIndices = append(ruleLineIndices, i)
			}
		}

		discardCount := len(ruleLineIndices) - req.RetainLines
		if discardCount <= 0 {
			return nil // 无需清理
		}

		indicesToDiscard := make(map[int]bool)
		for i := 0; i < discardCount; i++ {
			indicesToDiscard[ruleLineIndices[i]] = true
		}

		for i, line := range allLines {
			if !indicesToDiscard[i] {
				linesToKeep = append(linesToKeep, line)
			}
		}
	}

	err = os.WriteFile(logPath, []byte(strings.Join(linesToKeep, "\n")+"\n"), 0644)
	if err != nil {
		log.Printf("[LogCleanup] 写入清理后的日志文件失败: %v", err)
	} else {
		log.Println("[LogCleanup] 日志文件清理完成。")
	}
	return err
}

func (j *LogJanitor) performAutoCleanup() {
	configMutex.RLock()
	logSettings := currentConfig.Settings.Log
	logPath := filepath.Join(currentConfig.Settings.LogDirectory, "forwarder.log")
	configMutex.RUnlock()

	if logSettings.CleanupByTime.Enabled && logSettings.CleanupByTime.Value > 0 {
		performCleanup(logPath, LogCleanupRequest{
			CleanupType: "time",
			Mode:        logSettings.CleanupByTime.Mode,
			Value:       logSettings.CleanupByTime.Value,
		})
	}

	if logSettings.CleanupByLines.Enabled && logSettings.CleanupByLines.RetainLines > 0 {
		performCleanup(logPath, LogCleanupRequest{
			CleanupType: "total_lines",
			Value:       logSettings.CleanupByLines.RetainLines,
		})
	}

	for ruleName, ruleConfig := range logSettings.CleanupByRule {
		if ruleConfig.Enabled && ruleConfig.RetainLines > 0 {
			performCleanup(logPath, LogCleanupRequest{
				CleanupType: "rule_lines",
				RuleName:    ruleName,
				RetainLines: ruleConfig.RetainLines,
			})
		}
	}
}

// AddIPRequest 结构用于解析从前端发送的添加IP的请求
type AddIPRequest struct {
	Category string `json:"category"`
	ListName string `json:"listName"`
	IP       string `json:"ip"`
}

// reverseLines 翻转字符串切片
func reverseLines(lines []string) {
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
}

func main() {
	flag.Parse()

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Printf("未找到配置文件 %s，正在创建一个示例文件...", *configPath)
		exampleConfig := []byte(`
settings:
  log_directory: .
  ip_list_directory: ./ip_lists
  log:
    cleanup_by_time:
      enabled: false
      mode: days
      value: 7
    cleanup_by_lines:
      enabled: false
      retain_lines: 10000
    cleanup_by_rule: {}
global_access_control:
  mode: priority
ip_lists:
  whitelists:
    example-whitelist:
    - 127.0.0.1
rules:
- name: example-rule
  protocol: tcp
  listen_port: 8081
  forward_addr: 127.0.0.1
  forward_port: 80
  access_control:
    mode: disabled
  enabled: true
web_services: []
tls:
  enabled: false
waf:
  enabled: true
  default_action: "phase:2,deny,status:403,log"
  rule_sets:
  - name: "example-rules"
    source: "inline"
    rules:
    - "SecRuleEngine On"
    - "SecRule ARGS:testparam \"@contains test\" \"id:101,phase:2,block,msg:'Test rule triggered'\""
`)
		if err := os.WriteFile(*configPath, exampleConfig, 0644); err != nil {
			log.Fatalf("创建示例 config.yml 失败: %v", err)
		}
	}

	config, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载 config.yml 失败: %v", err)
	}
	currentConfig = config

	for _, dir := range []string{currentConfig.Settings.LogDirectory, currentConfig.Settings.IPListDirectory} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("创建目录 %s 失败: %v", dir, err)
		}
	}

	logPath := filepath.Join(currentConfig.Settings.LogDirectory, "forwarder.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	logJanitor := NewLogJanitor()
	logJanitor.Start()

	log.Println("配置加载成功。")

	certManager, err = NewCertManager(&currentConfig.TLS)
	if err != nil {
		log.Fatalf("初始化证书管理器失败: %v", err)
	}
	wafManager, err = NewWAFManager(&currentConfig.WAF, certManager.certDirectory)
	if err != nil {
		log.Fatalf("初始化 WAF 管理器失败: %v", err)
	}

	ipFilterManager = NewIPFilterManager(currentConfig)
	connManager := NewConnectionManager()
	forwarderManager = NewForwarderManager(connManager, ipFilterManager)
	webManager = NewWebManager(ipFilterManager, connManager, NewIPConnectionLimiter(), wafManager)
	updater = NewUpdater(ipFilterManager)

	updater.Start()

	log.Println("准备启动转发器...")
	for _, rule := range currentConfig.Rules {
		forwarderManager.StartRule(rule)
	}

	log.Println("准备启动Web服务...")
	for _, rule := range currentConfig.WebServices {
		webManager.StartRule(rule)
	}

	if currentConfig.WAF.Enabled {
		log.Println("[WAFManager] WAF 功能已启用。")
	} else {
		log.Println("[WAFManager] WAF 功能已禁用。")
	}

	log.Println("所有服务已在后台启动。")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		AllowCredentials: true,
	}))
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/ws" {
			clientIP := c.ClientIP()
			allowed, reason := ipFilterManager.IsAllowed(clientIP, RuleAccessControl{Mode: "disabled"})
			if !allowed {
				log.Printf("已拒绝来自 %s 的API/WS请求: %s", clientIP, reason)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "IP address rejected: " + reason})
				return
			}
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
		c.Next()
	})

	api := router.Group("/api")
	{
		// --- TLS APIs ---
		api.GET("/tls/certificates", func(c *gin.Context) {
			certs, err := certManager.ListCertificates()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法获取证书列表: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, certs)
		})
		api.GET("/tls", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.TLS)
		})
		api.PUT("/tls", func(c *gin.Context) {
			var newTLSConfig TLSConfig
			if err := c.ShouldBindJSON(&newTLSConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()})
				return
			}
			configMutex.Lock()
			currentConfig.TLS = newTLSConfig
			data, _ := yaml.Marshal(currentConfig)
			err := os.WriteFile(*configPath, data, 0644)
			configMutex.Unlock()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}
			certManager.UpdateTLSConfig(&newTLSConfig)
			c.JSON(http.StatusOK, gin.H{"message": "TLS设置已热重载成功，新域名将在后台任务中自动处理。"})
		})
		api.POST("/tls/request-cert", func(c *gin.Context) {
			domain := c.Query("domain")
			if domain == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 'domain' 参数"})
				return
			}
			go func() {
				err := certManager.RequestCertificate(domain)
				if err != nil {
					log.Printf("[API] 为域 %s 请求证书失败: %v", domain, err)
				}
			}()
			c.JSON(http.StatusOK, gin.H{"message": "已为域 " + domain + " 触发证书申请，请稍后查看日志。"})
		})
		// --- WAF APIs ---
		api.GET("/waf/status", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, gin.H{"enabled": currentConfig.WAF.Enabled})
		})
		// NEW: Get/Set full WAF config
		api.GET("/waf/config", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.WAF)
		})
		api.PUT("/waf/config", func(c *gin.Context) {
			var newWAFConfig WAFConfig
			if err := c.ShouldBindJSON(&newWAFConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()})
				return
			}

			configMutex.Lock()
			currentConfig.WAF = newWAFConfig
			data, _ := yaml.Marshal(currentConfig)
			err := os.WriteFile(*configPath, data, 0644)
			configMutex.Unlock()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}

			// Hot reload WAF manager
			newWafManager, err := NewWAFManager(&currentConfig.WAF, certManager.certDirectory)
			if err != nil {
				log.Printf("[WAFManager] 热重载失败: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "WAF 配置热重载失败"})
				return
			}
			wafManager = newWafManager
			webManager.wafManager = wafManager // Update webManager's instance too

			log.Println("[WAFManager] WAF 配置已热重载。")
			c.JSON(http.StatusOK, gin.H{"message": "WAF 设置已保存并热重载。"})
		})

		api.POST("/waf/toggle", func(c *gin.Context) {
			configMutex.Lock()
			defer configMutex.Unlock()
			currentConfig.WAF.Enabled = !currentConfig.WAF.Enabled
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile(*configPath, data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}
			if currentConfig.WAF.Enabled {
				log.Println("[WAFManager] WAF 功能已切换为: 启用。")
			} else {
				log.Println("[WAFManager] WAF 功能已切换为: 禁用。")
			}
			c.JSON(http.StatusOK, gin.H{"enabled": currentConfig.WAF.Enabled})
		})

		api.GET("/waf/rulesets", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.WAF.RuleSets)
		})
		
		// =================== START: ADDED CODE ===================
		// This handler gets the actual rules from a specific ruleset, fetching from file/url if necessary.
		api.GET("/waf/rulesets/:name/rules", func(c *gin.Context) {
			name := c.Param("name")
			if wafManager == nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "WAF Manager not initialized"})
				return
			}
			
			rules, err := wafManager.GetRuleSetRules(name)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
				return
			}
			
			// Ensure we return an empty array `[]` instead of `null` if there are no rules
			if rules == nil {
				rules = []string{}
			}

			c.JSON(http.StatusOK, rules)
		})
		// =================== END: ADDED CODE =====================

		api.POST("/waf/rulesets", func(c *gin.Context) {
			var newRuleSet WAFRuleSet
			if err := c.ShouldBindJSON(&newRuleSet); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则集数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			currentConfig.WAF.RuleSets = append(currentConfig.WAF.RuleSets, newRuleSet)
			data, _ := yaml.Marshal(currentConfig)
			err := os.WriteFile(*configPath, data, 0644)
			configMutex.Unlock()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}
			wafManager.loadRuleSet(newRuleSet) // Hot reload
			c.JSON(http.StatusOK, newRuleSet)
		})

		api.PUT("/waf/rulesets/:name", func(c *gin.Context) {
			ruleSetName := c.Param("name")
			var updatedRuleSet WAFRuleSet
			if err := c.ShouldBindJSON(&updatedRuleSet); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则集数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			found := false
			for i, rs := range currentConfig.WAF.RuleSets {
				if rs.Name == ruleSetName {
					currentConfig.WAF.RuleSets[i] = updatedRuleSet
					found = true
					break
				}
			}
			if !found {
				configMutex.Unlock()
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到 WAF 规则集: " + ruleSetName})
				return
			}
			data, _ := yaml.Marshal(currentConfig)
			err := os.WriteFile(*configPath, data, 0644)
			configMutex.Unlock()

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}

			wafManager.loadRuleSet(updatedRuleSet) // Hot reload
			c.JSON(http.StatusOK, updatedRuleSet)
		})

		api.DELETE("/waf/rulesets/:name", func(c *gin.Context) {
			ruleSetName := c.Param("name")
			configMutex.Lock()
			foundIndex := -1
			for i, rs := range currentConfig.WAF.RuleSets {
				if rs.Name == ruleSetName {
					foundIndex = i
					break
				}
			}
			if foundIndex == -1 {
				configMutex.Unlock()
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到 WAF 规则集: " + ruleSetName})
				return
			}
			currentConfig.WAF.RuleSets = append(currentConfig.WAF.RuleSets[:foundIndex], currentConfig.WAF.RuleSets[foundIndex+1:]...)
			data, _ := yaml.Marshal(currentConfig)
			err := os.WriteFile(*configPath, data, 0644)
			configMutex.Unlock()

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}
			// To-do: unload WAF from memory
			c.JSON(http.StatusOK, gin.H{"message": "WAF 规则集 '" + ruleSetName + "' 已成功删除"})
		})

		// --- Settings API ---
		api.GET("/settings", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig) // Return full config now
		})
		api.PUT("/settings", func(c *gin.Context) {
			var newConfig Config
			if err := c.ShouldBindJSON(&newConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()})
				return
			}
			configMutex.Lock()
			currentConfig.Settings = newConfig.Settings
			currentConfig.WAF = newConfig.WAF // Allow updating WAF through here as well
			// ... handle other parts of config if needed ...
			data, _ := yaml.Marshal(currentConfig)
			err := os.WriteFile(*configPath, data, 0644)
			configMutex.Unlock()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入 config.yml 失败"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "设置已保存。"})
		})

		// --- Web Services APIs ---
		api.GET("/web-rules", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.WebServices)
		})
		api.GET("/web-rules/status", func(c *gin.Context) {
			configMutex.RLock()
			rules := currentConfig.WebServices
			configMutex.RUnlock()
			statuses := webManager.GetRuleStatuses(rules)
			c.JSON(http.StatusOK, statuses)
		})
		api.POST("/web-rules", func(c *gin.Context) {
			var newRule WebServiceRule
			if err := c.ShouldBindJSON(&newRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			for _, r := range currentConfig.WebServices {
				if r.Name == newRule.Name {
					c.JSON(http.StatusConflict, gin.H{"error": "Web服务规则名称 '" + newRule.Name + "' 已存在"})
					return
				}
			}
			currentConfig.WebServices = append(currentConfig.WebServices, newRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			log.Printf("[Manager] 已添加新的Web服务规则 [%s]，正在启动服务...", newRule.Name)
			webManager.StartRule(newRule)
			c.JSON(http.StatusOK, newRule)
		})
		api.PUT("/web-rules/:name", func(c *gin.Context) {
			ruleName := c.Param("name")
			var updatedRule WebServiceRule
			if err := c.ShouldBindJSON(&updatedRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			found := false
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					log.Printf("[Manager] 已更新Web服务规则 [%s]，正在重启服务...", updatedRule.Name)
					webManager.StopRule(r.Name)
					currentConfig.WebServices[i] = updatedRule
					webManager.StartRule(updatedRule)
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到Web服务规则: " + ruleName})
				return
			}
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, updatedRule)
		})
		api.DELETE("/web-rules/:name", func(c *gin.Context) {
			ruleName := c.Param("name")
			configMutex.Lock()
			defer configMutex.Unlock()
			webManager.StopRule(ruleName)
			foundIndex := -1
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					foundIndex = i
					break
				}
			}
			if foundIndex == -1 {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到Web服务规则: " + ruleName})
				return
			}
			currentConfig.WebServices = append(currentConfig.WebServices[:foundIndex], currentConfig.WebServices[foundIndex+1:]...)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			log.Printf("[Manager] 已删除并停止Web服务规则 [%s]", ruleName)
			c.JSON(http.StatusOK, gin.H{"message": "Web服务规则 '" + ruleName + "' 已成功删除"})
		})
		api.POST("/web-rules/:name/toggle", func(c *gin.Context) {
			ruleName := c.Param("name")
			configMutex.Lock()
			defer configMutex.Unlock()
			var newState bool
			found := false
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					currentConfig.WebServices[i].Enabled = !r.Enabled
					newState = currentConfig.WebServices[i].Enabled
					log.Printf("[Manager] Web服务规则 [%s] 状态已切换为: %v", ruleName, newState)
					if newState {
						webManager.StartRule(currentConfig.WebServices[i])
					} else {
						webManager.StopRule(r.Name)
					}
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到Web服务规则: " + ruleName})
				return
			}
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "Web服务规则 '" + ruleName + "' 状态已切换", "enabled": newState})
		})

		api.POST("/web-rules/:name/sub-rules", func(c *gin.Context) {
			ruleName := c.Param("name")
			var subRule WebSubRule
			if err := c.ShouldBindJSON(&subRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的子规则数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			var parentRule *WebServiceRule
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					for _, sr := range r.SubRules {
						if sr.Name == subRule.Name {
							c.JSON(http.StatusConflict, gin.H{"error": "子规则名称 '" + subRule.Name + "' 已存在"})
							return
						}
					}
					currentConfig.WebServices[i].SubRules = append(r.SubRules, subRule)
					parentRule = &currentConfig.WebServices[i]
					break
				}
			}
			if parentRule == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到父规则: " + ruleName})
				return
			}
			log.Printf("[Manager] 因新增子规则 [%s]，正在重启 Web 服务 [%s]", subRule.Name, ruleName)
			webManager.RestartRule(*parentRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, subRule)
		})
		api.PUT("/web-rules/:name/sub-rules/:subRuleName", func(c *gin.Context) {
			ruleName := c.Param("name")
			subRuleName := c.Param("subRuleName")
			var updatedSubRule WebSubRule
			if err := c.ShouldBindJSON(&updatedSubRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的子规则数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			var parentRule *WebServiceRule
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					subFound := false
					for j, sr := range r.SubRules {
						if sr.Name == subRuleName {
							currentConfig.WebServices[i].SubRules[j] = updatedSubRule
							subFound = true
							break
						}
					}
					if !subFound {
						c.JSON(http.StatusNotFound, gin.H{"error": "未找到子规则: " + subRuleName})
						return
					}
					parentRule = &currentConfig.WebServices[i]
					break
				}
			}
			if parentRule == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到父规则: " + ruleName})
				return
			}
			log.Printf("[Manager] 因更新子规则 [%s]，正在重启 Web 服务 [%s]", updatedSubRule.Name, ruleName)
			webManager.RestartRule(*parentRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, updatedSubRule)
		})
		api.DELETE("/web-rules/:name/sub-rules/:subRuleName", func(c *gin.Context) {
			ruleName := c.Param("name")
			subRuleName := c.Param("subRuleName")
			configMutex.Lock()
			defer configMutex.Unlock()
			var parentRule *WebServiceRule
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					foundIndex := -1
					for j, sr := range r.SubRules {
						if sr.Name == subRuleName {
							foundIndex = j
							break
						}
					}
					if foundIndex == -1 {
						c.JSON(http.StatusNotFound, gin.H{"error": "未找到子规则: " + subRuleName})
						return
					}
					currentConfig.WebServices[i].SubRules = append(r.SubRules[:foundIndex], r.SubRules[foundIndex+1:]...)
					parentRule = &currentConfig.WebServices[i]
					break
				}
			}
			if parentRule == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到父规则: " + ruleName})
				return
			}
			log.Printf("[Manager] 因删除子规则 [%s]，正在重启 Web 服务 [%s]", subRuleName, ruleName)
			webManager.RestartRule(*parentRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "子规则 '" + subRuleName + "' 已成功删除"})
		})
		api.POST("/web-rules/:name/sub-rules/:subRuleName/toggle", func(c *gin.Context) {
			ruleName := c.Param("name")
			subRuleName := c.Param("subRuleName")
			configMutex.Lock()
			defer configMutex.Unlock()
			var parentRule *WebServiceRule
			var subRule *WebSubRule
			var newState bool
			for i, r := range currentConfig.WebServices {
				if r.Name == ruleName {
					parentRule = &currentConfig.WebServices[i]
					for j, sr := range r.SubRules {
						if sr.Name == subRuleName {
							subRule = &currentConfig.WebServices[i].SubRules[j]
							break
						}
					}
					break
				}
			}
			if parentRule == nil || subRule == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则或子规则"})
				return
			}
			subRule.Enabled = !subRule.Enabled
			newState = subRule.Enabled
			log.Printf("[%s %s] 状态已切换为: %v 并重启服务", ruleName, subRuleName, newState)
			webManager.RestartRule(*parentRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "子规则状态已切换", "enabled": newState})
		})

		api.GET("/rules", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.Rules)
		})
		api.GET("/rules/status", func(c *gin.Context) {
			configMutex.RLock()
			rules := currentConfig.Rules
			configMutex.RUnlock()
			statuses := forwarderManager.GetRuleStatuses(rules)
			c.JSON(http.StatusOK, statuses)
		})
		api.POST("/rules", func(c *gin.Context) {
			var newRule Rule
			if err := c.ShouldBindJSON(&newRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			for _, r := range currentConfig.Rules {
				if r.Name == newRule.Name {
					c.JSON(http.StatusConflict, gin.H{"error": "规则名称 '" + newRule.Name + "' 已存在"})
					return
				}
			}
			currentConfig.Rules = append(currentConfig.Rules, newRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			forwarderManager.StartRule(newRule)
			log.Printf("[Manager] 已添加并启动新规则 [%s]", newRule.Name)
			c.JSON(http.StatusOK, newRule)
		})
		api.PUT("/rules/:name", func(c *gin.Context) {
			ruleName := c.Param("name")
			var updatedRule Rule
			if err := c.ShouldBindJSON(&updatedRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			if ruleName != updatedRule.Name {
				for _, r := range currentConfig.Rules {
					if r.Name == updatedRule.Name {
						c.JSON(http.StatusConflict, gin.H{"error": "规则名称 '" + updatedRule.Name + "' 已存在"})
						return
					}
				}
			}
			found := false
			for i, r := range currentConfig.Rules {
				if r.Name == ruleName {
					forwarderManager.StopRule(r.Name)
					currentConfig.Rules[i] = updatedRule
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName})
				return
			}
			forwarderManager.StartRule(updatedRule)
			log.Printf("[Manager] 已更新规则 [%s]", updatedRule.Name)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, updatedRule)
		})
		api.DELETE("/rules/:name", func(c *gin.Context) {
			ruleName := c.Param("name")
			configMutex.Lock()
			defer configMutex.Unlock()
			forwarderManager.StopRule(ruleName)
			log.Printf("[Manager] 已停止规则 [%s]", ruleName)
			foundIndex := -1
			for i, r := range currentConfig.Rules {
				if r.Name == ruleName {
					foundIndex = i
					break
				}
			}
			if foundIndex == -1 {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName})
				return
			}
			currentConfig.Rules = append(currentConfig.Rules[:foundIndex], currentConfig.Rules[foundIndex+1:]...)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "规则 '" + ruleName + "' 已成功删除"})
		})
		api.POST("/rules/:name/toggle", func(c *gin.Context) {
			ruleName := c.Param("name")
			configMutex.Lock()
			defer configMutex.Unlock()
			var newState bool
			found := false
			for i, r := range currentConfig.Rules {
				if r.Name == ruleName {
					currentConfig.Rules[i].Enabled = !r.Enabled
					newState = currentConfig.Rules[i].Enabled
					if newState {
						forwarderManager.StartRule(currentConfig.Rules[i])
					} else {
						forwarderManager.StopRule(ruleName)
					}
					log.Printf("[Manager] 规则 [%s] 状态已切换为: %v", ruleName, newState)
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName})
				return
			}
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile(*configPath, data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "规则 '" + ruleName + "' 状态已切换", "enabled": newState})
		})

		// --- LOGS APIs ---
		api.GET("/logs", func(c *gin.Context) {
			ruleFilter := c.Query("rule")
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "50"))
			if page < 1 {
				page = 1
			}
			if pageSize < 1 {
				pageSize = 50
			}

			configMutex.RLock()
			logPath := filepath.Join(currentConfig.Settings.LogDirectory, "forwarder.log")
			configMutex.RUnlock()

			file, err := os.Open(logPath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开日志文件"})
				return
			}
			defer file.Close()

			var filteredLines []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if ruleFilter == "" || ruleFilter == "all" {
					filteredLines = append(filteredLines, line)
				} else {

					re := regexp.MustCompile(`\[` + regexp.QuoteMeta(ruleFilter) + `(\s|\])`)
					if re.MatchString(line) {
						filteredLines = append(filteredLines, line)
					}
				}
			}

			reverseLines(filteredLines)

			totalLogs := len(filteredLines)
			totalPages := int(math.Ceil(float64(totalLogs) / float64(pageSize)))
			start := (page - 1) * pageSize
			end := start + pageSize
			if start > totalLogs {
				start = totalLogs
			}
			if end > totalLogs {
				end = totalLogs
			}

			paginatedLogs := filteredLines[start:end]

			c.JSON(http.StatusOK, gin.H{
				"logs":        paginatedLogs,
				"currentPage": page,
				"totalPages":  totalPages,
				"totalLogs":   totalLogs,
			})
		})

		api.GET("/logs/waf", func(c *gin.Context) {
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "50"))
			if page < 1 {
				page = 1
			}
			if pageSize < 1 {
				pageSize = 50
			}

			configMutex.RLock()
			logPath := filepath.Join(currentConfig.Settings.LogDirectory, "waf_audit.log")
			configMutex.RUnlock()

			file, err := os.Open(logPath)
			if err != nil {
				if os.IsNotExist(err) {
					c.JSON(http.StatusOK, gin.H{
						"logs":        []string{},
						"currentPage": 1,
						"totalPages":  0,
						"totalLogs":   0,
					})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开WAF日志文件"})
				return
			}
			defer file.Close()

			var wafLogs []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				wafLogs = append(wafLogs, scanner.Text())
			}

			reverseLines(wafLogs)

			totalLogs := len(wafLogs)
			totalPages := int(math.Ceil(float64(totalLogs) / float64(pageSize)))
			start := (page - 1) * pageSize
			end := start + pageSize
			if start > totalLogs {
				start = totalLogs
			}
			if end > totalLogs {
				end = totalLogs
			}

			paginatedLogs := wafLogs[start:end]

			c.JSON(http.StatusOK, gin.H{
				"logs":        paginatedLogs,
				"currentPage": page,
				"totalPages":  totalPages,
				"totalLogs":   totalLogs,
			})
		})

		api.GET("/logs/cert-manager", func(c *gin.Context) {
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "50"))
			if page < 1 {
				page = 1
			}
			if pageSize < 1 {
				pageSize = 50
			}

			configMutex.RLock()
			logPath := filepath.Join(currentConfig.Settings.LogDirectory, "forwarder.log")
			configMutex.RUnlock()

			file, err := os.Open(logPath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开日志文件"})
				return
			}
			defer file.Close()

			var certLogs []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "[CertManager]") || strings.Contains(line, "[API]") || strings.Contains(line, "acme:") || strings.Contains(line, "[ACMEUser]") {
					certLogs = append(certLogs, line)
				}
			}

			reverseLines(certLogs)

			totalLogs := len(certLogs)
			totalPages := int(math.Ceil(float64(totalLogs) / float64(pageSize)))
			start := (page - 1) * pageSize
			end := start + pageSize
			if start > totalLogs {
				start = totalLogs
			}
			if end > totalLogs {
				end = totalLogs
			}

			paginatedLogs := certLogs[start:end]

			c.JSON(http.StatusOK, gin.H{
				"logs":        paginatedLogs,
				"currentPage": page,
				"totalPages":  totalPages,
				"totalLogs":   totalLogs,
			})
		})

		api.GET("/logs/domain/:domain", func(c *gin.Context) {
			domain := c.Param("domain")

			configMutex.RLock()
			logPath := filepath.Join(currentConfig.Settings.LogDirectory, "forwarder.log")
			configMutex.RUnlock()

			file, err := os.Open(logPath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开日志文件"})
				return
			}
			defer file.Close()

			var domainLogs []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, domain) {
					domainLogs = append(domainLogs, line)
				}
			}
			reverseLines(domainLogs)
			c.JSON(http.StatusOK, domainLogs)
		})

		api.POST("/logs/cleanup", func(c *gin.Context) {
			var req LogCleanupRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据: " + err.Error()})
				return
			}
			configMutex.RLock()
			logPath := filepath.Join(currentConfig.Settings.LogDirectory, "forwarder.log")
			configMutex.RUnlock()
			err := performCleanup(logPath, req)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "日志清理失败: " + err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "日志清理任务已成功执行。"})
		})

		api.POST("/actions/restart", func(c *gin.Context) {
			log.Println("[Manager] 收到重启请求，服务将在1秒后优雅退出...")
			c.JSON(http.StatusOK, gin.H{"message": "服务正在重启..."})
			go func() {
				time.Sleep(1 * time.Second)
				stop()
			}()
		})

		api.GET("/ip-lists", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.IPLists)
		})
		api.GET("/ip-lists/status", func(c *gin.Context) {
			ipFilterManager.mu.RLock()
			defer ipFilterManager.mu.RUnlock()
			statuses := make(map[string]gin.H)
			for name, list := range ipFilterManager.lists {
				statuses[name] = gin.H{
					"count":       list.Count,
					"lastUpdated": list.LastUpdated,
				}
			}
			c.JSON(http.StatusOK, statuses)
		})
		api.GET("/ip-lists/file/:name", func(c *gin.Context) {
			listName := c.Param("name")
			configMutex.RLock()
			filePath := filepath.Join(currentConfig.Settings.IPListDirectory, listName+".txt")
			configMutex.RUnlock()
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": "缓存文件未找到，请先至少更新一次。"})
				return
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "读取缓存文件失败: " + err.Error()})
				return
			}
			c.String(http.StatusOK, string(data))
		})
		api.POST("/ip-lists/add", func(c *gin.Context) {
			var req AddIPRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			var list []string
			var ok bool
			var listUpdated bool
			checkAndAppend := func(l []string) ([]string, bool) {
				for _, ip := range l {
					if ip == req.IP {
						return l, false
					}
				}
				return append(l, req.IP), true
			}
			switch req.Category {
			case "whitelists":
				if list, ok = currentConfig.IPLists.Whitelists[req.ListName]; ok {
					currentConfig.IPLists.Whitelists[req.ListName], listUpdated = checkAndAppend(list)
				}
			case "blacklists":
				if list, ok = currentConfig.IPLists.Blacklists[req.ListName]; ok {
					currentConfig.IPLists.Blacklists[req.ListName], listUpdated = checkAndAppend(list)
				}
			case "ip_sets":
				if list, ok = currentConfig.IPLists.IPSets[req.ListName]; ok {
					currentConfig.IPLists.IPSets[req.ListName], listUpdated = checkAndAppend(list)
				}
			}
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到名为 '" + req.ListName + "' 的名单，或该名单不支持手动添加。"})
				return
			}
			if !listUpdated {
				c.JSON(http.StatusOK, gin.H{"message": "IP " + req.IP + " 已存在于名单 '" + req.ListName + "' 中"})
				return
			}
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile(*configPath, data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置文件失败"})
				return
			}
			ipFilterManager.UpdateAllManualLists(currentConfig.IPLists)
			c.JSON(http.StatusOK, gin.H{"message": "成功将IP " + req.IP + " 添加到名单 '" + req.ListName + "'"})
		})
		api.PUT("/ip-lists", func(c *gin.Context) {
			var newIPLists IPLists
			if err := c.ShouldBindJSON(&newIPLists); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			existingNames := make(map[string]bool)
			for name := range newIPLists.Whitelists {
				existingNames[name] = true
			}
			for name := range newIPLists.Blacklists {
				existingNames[name] = true
			}
			for name := range newIPLists.IPSets {
				existingNames[name] = true
			}
			for name := range newIPLists.CountryIPLists {
				existingNames[name] = true
			}
			for name := range newIPLists.UrlIpSets {
				existingNames[name] = true
			}

			for name := range currentConfig.IPLists.CountryIPLists {
				if !existingNames[name] {
					ipFilterManager.RemoveList(name)
					filePath := filepath.Join(currentConfig.Settings.IPListDirectory, name+".txt")
					os.Remove(filePath)
				}
			}
			for name := range currentConfig.IPLists.UrlIpSets {
				if !existingNames[name] {
					ipFilterManager.RemoveList(name)
					filePath := filepath.Join(currentConfig.Settings.IPListDirectory, name+".txt")
					os.Remove(filePath)
				}
			}

			for name := range currentConfig.IPLists.Whitelists {
				if !existingNames[name] {
					ipFilterManager.RemoveList(name)
				}
			}
			for name := range currentConfig.IPLists.Blacklists {
				if !existingNames[name] {
					ipFilterManager.RemoveList(name)
				}
			}
			for name := range currentConfig.IPLists.IPSets {
				if !existingNames[name] {
					ipFilterManager.RemoveList(name)
				}
			}

			currentConfig.IPLists = newIPLists
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile(*configPath, data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置文件失败"})
				return
			}
			ipFilterManager.UpdateAllManualLists(currentConfig.IPLists)
			go updater.runUpdateCycle()
			log.Println("[Manager] IP名单配置已更新并立即生效。")
			c.JSON(http.StatusOK, currentConfig.IPLists)
		})
		api.POST("/ip-lists/:name/refresh", func(c *gin.Context) {
			listName := c.Param("name")
			configMutex.RLock()
			var listConfig *IPListConfig
			var ok bool
			allDynamicLists := make(map[string]*IPListConfig)
			for name, config := range currentConfig.IPLists.CountryIPLists {
				allDynamicLists[name] = config
			}
			for name, config := range currentConfig.IPLists.UrlIpSets {
				allDynamicLists[name] = config
			}
			listConfig, ok = allDynamicLists[listName]
			configMutex.RUnlock()
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到动态IP名单: " + listName})
				return
			}
			go func() {
				if err := updater.updateList(listName, listConfig); err == nil {
					log.Printf("[API] 已成功为名单 '%s' 触发手动刷新。", listName)
				} else {
					log.Printf("[API] 为名单 '%s' 触发手动刷新失败: %v", listName, err)
				}
			}()
			c.JSON(http.StatusOK, gin.H{"message": "已触发对名单 '" + listName + "' 的后台刷新。"})
		})
		api.POST("/connections/:id/disconnect", func(c *gin.Context) {
			idStr := c.Param("id")
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的连接ID"})
				return
			}
			if connManager.Disconnect(id) {
				c.JSON(http.StatusOK, gin.H{"message": "连接 " + idStr + " 已断开"})
			} else {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到连接 " + idStr})
			}
		})
		api.GET("/global-acl", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.GlobalAccessControl)
		})
		api.PUT("/global-acl", func(c *gin.Context) {
			var newGlobalAC GlobalAccessControl
			if err := c.ShouldBindJSON(&newGlobalAC); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()})
				return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			currentConfig.GlobalAccessControl = newGlobalAC
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile(*configPath, data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置文件失败"})
				return
			}
			ipFilterManager.UpdateGlobalAC(newGlobalAC)
			c.JSON(http.StatusOK, gin.H{"message": "全局访问控制配置已更新并立即生效。"})
		})
	}

	router.GET("/ws", func(c *gin.Context) { connManager.ServeWs(c.Writer, c.Request) })

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		log.Println("Web API 和 WebSocket 服务器启动于 http://localhost:8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("启动 Web 服务器失败: %v", err)
		}
	}()

	<-ctx.Done()
	stop()

	log.Println("收到关停信号，正在准备关闭服务...")

	configMutex.RLock()
	allRules := currentConfig.Rules
	allWebRules := currentConfig.WebServices
	configMutex.RUnlock()

	for _, rule := range allRules {
		forwarderManager.StopRule(rule.Name)
	}
	for _, rule := range allWebRules {
		webManager.StopRule(rule.Name)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Web服务器强制关闭失败: %v", err)
	}

	log.Println("所有服务已成功关闭。")
}