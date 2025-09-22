package main

import (
	"bufio"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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
	updater          *Updater
)

// reverseLines 翻转字符串切片
func reverseLines(lines []string) {
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
}

func main() {
	logFile, err := os.OpenFile("forwarder.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	if _, err := os.Stat("config.yml"); os.IsNotExist(err) {
		log.Println("未找到 config.yml，正在创建一个示例文件...")
		exampleConfig := []byte(`
global_access_control:
  mode: priority
  whitelist_enabled: false
  whitelist_list_name: ""
  blacklist_enabled: false
  blacklist_list_name: ""
ip_lists:
  whitelists:
    example-whitelist:
      - "192.168.1.1"
  blacklists:
    example-blacklist:
      - "8.8.8.8"
  ip_sets:
    trusted-country:
      - "1.0.0.0/8"
  country_ip_lists:
    cn-ips:
      type: country
      source: CN
rules:
  - name: "example-rule"
    protocol: "tcp"
    listen_addr: ""
    listen_port: 2222
    forward_addr: "127.0.0.1"
    forward_port: 22
    access_control:
      mode: "whitelist"
      list_name: "example-whitelist"
    enabled: true
`)
		if err := os.WriteFile("config.yml", exampleConfig, 0644); err != nil {
			log.Fatalf("创建示例 config.yml 失败: %v", err)
		}
	}

	config, err := LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("加载 config.yml 失败: %v", err)
	}
	currentConfig = config
	log.Println("配置加载成功。")

	ipFilterManager = NewIPFilterManager(currentConfig)
	connManager := NewConnectionManager()
	forwarderManager = NewForwarderManager(connManager, ipFilterManager)
	updater = NewUpdater(ipFilterManager)

	updater.Start() // 启动后台更新服务

	log.Println("准备启动转发器...")
	for _, rule := range currentConfig.Rules {
		if rule.Enabled {
			forwarderManager.StartRule(rule)
		} else {
			log.Printf("规则 [%s] 已被禁用，跳过启动。", rule.Name)
		}
	}
	log.Println("所有转发器已在后台启动。")

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
		api.GET("/rules", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.Rules)
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
			os.WriteFile("config.yml", data, 0644)
			if newRule.Enabled {
				forwarderManager.StartRule(newRule)
			}
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
			if updatedRule.Enabled {
				forwarderManager.StartRule(updatedRule)
			}
			log.Printf("[Manager] 已更新规则 [%s]", updatedRule.Name)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile("config.yml", data, 0644)
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
			os.WriteFile("config.yml", data, 0644)
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
						log.Printf("[Manager] 已启动规则 [%s]", ruleName)
					} else {
						forwarderManager.StopRule(ruleName)
						log.Printf("[Manager] 已停止规则 [%s]", ruleName)
					}
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName})
				return
			}
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile("config.yml", data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "规则 '" + ruleName + "' 状态已切换", "enabled": newState})
		})

		api.GET("/logs", func(c *gin.Context) {
			ruleFilter := c.Query("rule")
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))

			if page < 1 {
				page = 1
			}
			if pageSize < 1 {
				pageSize = 20
			}

			file, err := os.Open("forwarder.log")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "无法打开日志文件"})
				return
			}
			defer file.Close()

			var allLines []string
			scanner := bufio.NewScanner(file)
			filterTag := "[" + ruleFilter + "]"

			for scanner.Scan() {
				line := scanner.Text()
				if ruleFilter == "" || ruleFilter == "all" || strings.Contains(line, filterTag) {
					allLines = append(allLines, line)
				}
			}

			reverseLines(allLines)

			totalLogs := len(allLines)
			totalPages := int(math.Ceil(float64(totalLogs) / float64(pageSize)))
			start := (page - 1) * pageSize
			end := start + pageSize

			if start > totalLogs {
				start = totalLogs
			}
			if end > totalLogs {
				end = totalLogs
			}

			paginatedLogs := allLines[start:end]

			c.JSON(http.StatusOK, gin.H{
				"logs":        paginatedLogs,
				"currentPage": page,
				"totalPages":  totalPages,
				"totalLogs":   totalLogs,
			})
		})

		api.POST("/actions/restart", func(c *gin.Context) {
			log.Println("[Manager] 收到重启请求，服务将在1秒后退出...")
			c.JSON(http.StatusOK, gin.H{"message": "服务正在重启..."})
			go func() {
				time.Sleep(1 * time.Second)
				os.Exit(0)
			}()
		})
		
		api.GET("/ip-lists", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.IPLists)
		})
		
		api.PUT("/ip-lists", func(c *gin.Context) {
			var newIPLists IPLists
			if err := c.ShouldBindJSON(&newIPLists); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()})
				return
			}
			
			configMutex.Lock()
			defer configMutex.Unlock()
			
			// Handle deleted lists
			// Note: This logic needs to be more robust if lists can be renamed.
			// For now, it handles simple deletions across all categories.
			existingNames := make(map[string]bool)
			for name := range newIPLists.Whitelists { existingNames[name] = true }
			for name := range newIPLists.Blacklists { existingNames[name] = true }
			for name := range newIPLists.IPSets { existingNames[name] = true }
			for name := range newIPLists.CountryIPLists { existingNames[name] = true }

			for name := range currentConfig.IPLists.Whitelists { if !existingNames[name] { ipFilterManager.RemoveList(name) } }
			for name := range currentConfig.IPLists.Blacklists { if !existingNames[name] { ipFilterManager.RemoveList(name) } }
			for name := range currentConfig.IPLists.IPSets { if !existingNames[name] { ipFilterManager.RemoveList(name) } }
			for name := range currentConfig.IPLists.CountryIPLists { if !existingNames[name] { ipFilterManager.RemoveList(name) } }
			
			currentConfig.IPLists = newIPLists
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile("config.yml", data, 0644); err != nil {
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
			listConfig, ok := currentConfig.IPLists.CountryIPLists[listName]
			configMutex.RUnlock()

			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到动态IP名单: " + listName})
				return
			}

			go updater.updateList(listName, listConfig)

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
			if err := os.WriteFile("config.yml", data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置文件失败"})
				return
			}
			ipFilterManager.UpdateGlobalAC(newGlobalAC)
			c.JSON(http.StatusOK, gin.H{"message": "全局访问控制配置已更新并立即生效。"})
		})
	}

	router.GET("/ws", func(c *gin.Context) { connManager.ServeWs(c.Writer, c.Request) })

	log.Println("Web API 和 WebSocket 服务器启动于 http://localhost:8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("启动 Web 服务器失败: %v", err)
	}
}