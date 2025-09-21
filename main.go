// cnnlei/network/network-33ab537e85847c302b55c126d843f77b047a1244/main.go
package main

import (
	"bufio"
	"io"
	"log"
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
	configMutex     = &sync.RWMutex{}
	currentConfig   *Config
	ipFilterManager *IPFilterManager
)

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
  admin-ips:
    - "127.0.0.1"
  blocked-ips:
    - "0.0.0.0"
rules:
  - name: "example-rule"
    protocol: "tcp"
    listen_addr: ""
    listen_port: 2222
    forward_addr: "127.0.0.1"
    forward_port: 22
    access_control:
      mode: "disabled"
      list_name: ""
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

	ipFilterManager = NewIPFilterManager(currentConfig.IPLists, currentConfig.GlobalAccessControl)
	connManager := NewConnectionManager()

	log.Println("准备启动转发器...")
	for _, rule := range currentConfig.Rules {
		if !rule.Enabled {
			log.Printf("规则 [%s] 已被禁用，跳过启动。", rule.Name)
			continue
		}
		
		proto := strings.ToLower(rule.Protocol)
		
		if strings.Contains(proto, "tcp") {
			tcpRule := rule
			if strings.Contains(proto, ",") { // More robust check for combined protocols
				baseProto := "tcp"
				if tcpRule.ListenAddr == "0.0.0.0" {
					tcpRule.Protocol = baseProto + "4"
				} else if tcpRule.ListenAddr == "::" {
					tcpRule.Protocol = baseProto + "6"
				} else {
					tcpRule.Protocol = baseProto
				}
			}
			go startTCPForwarder(tcpRule, connManager, ipFilterManager)
		}
		
		if strings.Contains(proto, "udp") {
			udpRule := rule
			if strings.Contains(proto, ",") {
				baseProto := "udp"
				if udpRule.ListenAddr == "0.0.0.0" {
					udpRule.Protocol = baseProto + "4"
				} else if udpRule.ListenAddr == "::" {
					udpRule.Protocol = baseProto + "6"
				} else {
					udpRule.Protocol = baseProto
				}
			}
			go startUDPForwarder(udpRule, connManager, ipFilterManager)
		}
		
		if !strings.Contains(proto, "tcp") && !strings.Contains(proto, "udp") {
			log.Printf("警告: 规则 [%s] 使用了不支持的协议 '%s'，已跳过。", rule.Name, rule.Protocol)
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
		// ... Rules, Logs, Actions, Connections, IP Lists APIs remain unchanged ...
		api.GET("/rules", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.Rules)
		})
		api.POST("/rules", func(c *gin.Context) {
			var newRule Rule
			if err := c.ShouldBindJSON(&newRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则数据: " + err.Error()}); return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			for _, r := range currentConfig.Rules {
				if r.Name == newRule.Name {
					c.JSON(http.StatusConflict, gin.H{"error": "规则名称 '" + newRule.Name + "' 已存在"}); return
				}
			}
			currentConfig.Rules = append(currentConfig.Rules, newRule)
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile("config.yml", data, 0644)
			c.JSON(http.StatusOK, newRule)
		})
		api.PUT("/rules/:name", func(c *gin.Context) {
			ruleName := c.Param("name")
			var updatedRule Rule
			if err := c.ShouldBindJSON(&updatedRule); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则数据: " + err.Error()}); return
			}

			configMutex.Lock()
			defer configMutex.Unlock()

			if ruleName != updatedRule.Name {
				for _, r := range currentConfig.Rules {
					if r.Name == updatedRule.Name {
						c.JSON(http.StatusConflict, gin.H{"error": "规则名称 '" + updatedRule.Name + "' 已存在"}); return
					}
				}
			}

			found := false
			for i, r := range currentConfig.Rules {
				if r.Name == ruleName {
					currentConfig.Rules[i] = updatedRule
					found = true
					break
				}
			}
			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName}); return
			}
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile("config.yml", data, 0644)
			c.JSON(http.StatusOK, updatedRule)
		})
		api.DELETE("/rules/:name", func(c *gin.Context) {
			ruleName := c.Param("name")
			configMutex.Lock()
			defer configMutex.Unlock()
			foundIndex := -1
			for i, r := range currentConfig.Rules {
				if r.Name == ruleName {
					foundIndex = i
					break
				}
			}
			if foundIndex == -1 {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName}); return
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

			found := false
			var newState bool
			for i, r := range currentConfig.Rules {
				if r.Name == ruleName {
					currentConfig.Rules[i].Enabled = !r.Enabled
					newState = currentConfig.Rules[i].Enabled
					found = true
					break
				}
			}

			if !found {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到规则: " + ruleName}); return
			}

			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile("config.yml", data, 0644)
			c.JSON(http.StatusOK, gin.H{"message": "规则 '" + ruleName + "' 状态已切换", "enabled": newState})
		})

		api.GET("/logs", func(c *gin.Context) {
			c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			ruleFilter := c.Query("rule")
			file, err := os.Open("forwarder.log")
			if err != nil { c.String(http.StatusInternalServerError, "无法打开日志文件"); return }
			defer file.Close()
			if ruleFilter == "" || ruleFilter == "all" {
				logData, _ := io.ReadAll(file)
				c.String(http.StatusOK, string(logData))
				return
			}
			var filteredLogs strings.Builder
			scanner := bufio.NewScanner(file)
			filterTag := "[" + ruleFilter + "]"
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, filterTag) {
					filteredLogs.WriteString(line + "\n")
				}
			}
			c.String(http.StatusOK, filteredLogs.String())
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
			var newIPLists map[string][]string
			if err := c.ShouldBindJSON(&newIPLists); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()}); return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			currentConfig.IPLists = newIPLists
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile("config.yml", data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置文件失败"}); return
			}
			ipFilterManager.UpdateLists(currentConfig.IPLists)
			log.Println("[Manager] IP名单配置已更新并立即生效。")
			c.JSON(http.StatusOK, currentConfig.IPLists)
		})
		
		api.POST("/connections/:id/disconnect", func(c *gin.Context) {
			idStr := c.Param("id")
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的连接ID"}); return
			}
			if connManager.Disconnect(id) {
				c.JSON(http.StatusOK, gin.H{"message": "连接 " + idStr + " 已断开"})
			} else {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到连接 " + idStr})
			}
		})

		api.POST("/ip-lists/:name/add", func(c *gin.Context) {
			listName := c.Param("name")
			var payload struct {
				IP string `json:"ip"`
			}
			if err := c.ShouldBindJSON(&payload); err != nil || payload.IP == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的IP数据"}); return
			}
			configMutex.Lock()
			defer configMutex.Unlock()
			if list, ok := currentConfig.IPLists[listName]; ok {
				for _, ip := range list {
					if ip == payload.IP {
						c.JSON(http.StatusConflict, gin.H{"message": "IP " + payload.IP + " 已存在于 " + listName}); return
					}
				}
				currentConfig.IPLists[listName] = append(list, payload.IP)
			} else {
				c.JSON(http.StatusNotFound, gin.H{"error": "未找到IP名单: " + listName}); return
			}
			data, _ := yaml.Marshal(currentConfig)
			os.WriteFile("config.yml", data, 0644)
			ipFilterManager.UpdateLists(currentConfig.IPLists)
			c.JSON(http.StatusOK, gin.H{"message": "IP " + payload.IP + " 已添加到 " + listName})
		})

		// --- 修正: 全局访问控制 API ---
		api.GET("/global-acl", func(c *gin.Context) {
			configMutex.RLock()
			defer configMutex.RUnlock()
			c.JSON(http.StatusOK, currentConfig.GlobalAccessControl)
		})

		api.PUT("/global-acl", func(c *gin.Context) {
			var newGlobalAC GlobalAccessControl
			if err := c.ShouldBindJSON(&newGlobalAC); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的数据格式: " + err.Error()}); return
			}
			configMutex.Lock()
			defer configMutex.Unlock()

			currentConfig.GlobalAccessControl = newGlobalAC
			data, _ := yaml.Marshal(currentConfig)
			if err := os.WriteFile("config.yml", data, 0644); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "写入配置文件失败"}); return
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