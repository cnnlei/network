package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
)

// WAFManager 管理多个规则集
type WAFManager struct {
	mu          sync.RWMutex
	wafs        map[string]coraza.WAF
	config      *WAFConfig
	certDir     string
	auditLogger *log.Logger // 新增：用于向 waf_audit.log 写入简洁日志的记录器
}

// NewWAFManager 初始化 WAFManager
func NewWAFManager(cfg *WAFConfig, certDir string) (*WAFManager, error) {
	wm := &WAFManager{
		wafs:    make(map[string]coraza.WAF),
		config:  cfg,
		certDir: certDir,
	}

	if cfg.Enabled {
		// 初始化用于写入简洁拦截日志的记录器
		configMutex.RLock()
		logDir := currentConfig.Settings.LogDirectory
		configMutex.RUnlock()
		if logDir == "" {
			logDir = "." // 如果未设置日志目录，则默认为当前目录
		}

		auditLogPath := filepath.Join(logDir, "waf_audit.log")
		file, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open WAF audit log file for manual logging: %w", err)
		}
		wm.auditLogger = log.New(file, "", log.LstdFlags)

		if err := wm.loadAllRuleSets(); err != nil {
			// 注意：如果加载失败，文件句柄不会被关闭，但这在程序启动失败的场景下通常不是问题
			return nil, err
		}
	}

	return wm, nil
}

// loadAllRuleSets 加载配置的所有规则集
func (wm *WAFManager) loadAllRuleSets() error {
	for _, rs := range wm.config.RuleSets {
		if err := wm.loadRuleSet(rs); err != nil {
			logMessage := fmt.Sprintf("[WAFManager] Error loading rule set '%s': %v", rs.Name, err)
			log.Print(logMessage)
			if wm.auditLogger != nil {
				wm.auditLogger.Print(logMessage)
			}
		}
	}
	return nil
}

// loadRuleSet 加载单个规则集
func (wm *WAFManager) loadRuleSet(rs WAFRuleSet) error {
	rules := strings.Join(rs.Rules, "\n")

	// 整合来自不同来源的规则
	if rs.Source == "url" && rs.Path != "" {
		resp, err := http.Get(rs.Path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		rules += "\n" + string(body)
	} else if rs.Source == "file" && rs.Path != "" {
		content, err := ioutil.ReadFile(rs.Path)
		if err != nil {
			return err
		}
		rules += "\n" + string(content)
	}

	configMutex.RLock()
	logDir := currentConfig.Settings.LogDirectory
	defaultAction := currentConfig.WAF.DefaultAction
	configMutex.RUnlock()
	auditLogPath := filepath.Join(logDir, "waf_audit.log")

	// 创建 Coraza 配置
	conf := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRequestBodyAccess On").
		WithDirectives("SecRequestBodyLimit 13107200").
		WithDirectives("SecRequestBodyNoFilesLimit 131072").
		WithDirectives("SecRequestBodyInMemoryLimit 131072").
		WithDirectives("SecRequestBodyLimitAction Reject").
		WithDirectives("SecAuditEngine On").
		WithDirectives("SecAuditLogFormat JSON").
		WithDirectives("SecAuditLogParts ABCDEFGHIJKZ"). // 开启最详细的JSON日志，以便看到args等字段
		WithDirectives("SecAuditLog " + auditLogPath)

	// 如果 DefaultAction 不为空，则应用它
	if defaultAction != "" {
		conf = conf.WithDirectives("SecDefaultAction \"" + defaultAction + "\"")
	}

	// 最后加载规则
	conf = conf.WithDirectives(rules)

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		return err
	}

	wm.mu.Lock()
	wm.wafs[rs.Name] = waf
	wm.mu.Unlock()

	logMessage := fmt.Sprintf("[WAFManager] Successfully loaded WAF rule set: %s", rs.Name)
	log.Print(logMessage)
	if wm.auditLogger != nil {
		wm.auditLogger.Print(logMessage)
	}
	return nil
}

// GetWAF 获取指定名称的 WAF
func (wm *WAFManager) GetWAF(name string) (coraza.WAF, bool) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	waf, ok := wm.wafs[name]
	return waf, ok
}

// Middleware 创建 HTTP 中间件，支持完整请求/响应拦截
func (wm *WAFManager) Middleware(next http.Handler, ruleSetName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configMutex.RLock()
		isWafEnabled := currentConfig.WAF.Enabled
		configMutex.RUnlock()

		if !isWafEnabled {
			next.ServeHTTP(w, r)
			return
		}

		waf, ok := wm.GetWAF(ruleSetName)
		if !ok || waf == nil {
			next.ServeHTTP(w, r)
			return
		}

		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging() // Coraza 在这里写入详细的 JSON 日志
			tx.Close()
		}()

		// 强制解析 URL 参数和 POST 表单
		if err := r.ParseForm(); err != nil {
			logMessage := fmt.Sprintf("[WAFManager] Error parsing form: %v", err)
			log.Print(logMessage)
			if wm.auditLogger != nil {
				wm.auditLogger.Print(logMessage)
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// 处理客户端地址
		client, cport, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			logMessage := fmt.Sprintf("[WAFManager] Error parsing remote address: %v", err)
			log.Print(logMessage)
			if wm.auditLogger != nil {
				wm.auditLogger.Print(logMessage)
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		cporti, _ := strconv.Atoi(cport)

		// 处理服务端地址
		host, sport, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
			sport = ""
		}
		sporti, _ := strconv.Atoi(sport)

		// 1️⃣ 处理连接和请求行
		tx.ProcessConnection(client, cporti, host, sporti)
		tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

		// 2️⃣ 处理请求头
		for k, vv := range r.Header {
			for _, v := range vv {
				tx.AddRequestHeader(k, v)
			}
		}
		if it := tx.ProcessRequestHeaders(); it != nil {
    logMessage := fmt.Sprintf("[WAFManager] BLOCK Request Headers. RuleID=%d URI=%s", it.RuleID, r.RequestURI)
    log.Print(logMessage)
    if wm.auditLogger != nil {
        wm.auditLogger.Println(logMessage)
    }
    
    // START: 添加自定义响应体逻辑
    configMutex.RLock()
    defaultActionBody := currentConfig.WAF.DefaultActionBody
    configMutex.RUnlock()
    
    w.WriteHeader(it.Status)
    if defaultActionBody != "" {
        w.Write([]byte(defaultActionBody))
    }
    // END: 添加自定义响应体逻辑
    return
}

		// 3️⃣ 处理请求体 (JSON/XML/Raw POST)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, err = ioutil.ReadAll(r.Body)
			if err != nil {
				logMessage := fmt.Sprintf("[WAFManager] Error reading request body: %v", err)
				log.Print(logMessage)
				if wm.auditLogger != nil {
					wm.auditLogger.Print(logMessage)
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			r.Body.Close()
			r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

			if it, _, err := tx.ReadRequestBodyFrom(bytes.NewReader(bodyBytes)); err != nil || it != nil {
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				} else {
					w.WriteHeader(it.Status)
				}
				return
			}

			// 修正：正确处理 ProcessRequestBody 的两个返回值
			if it, err := tx.ProcessRequestBody(); err != nil || it != nil {
				if err != nil {
					logMessage := fmt.Sprintf("[WAFManager] Error processing request body: %v", err)
					log.Print(logMessage)
					if wm.auditLogger != nil {
						wm.auditLogger.Print(logMessage)
					}
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				if it != nil {
					logMessage := fmt.Sprintf("[WAFManager] BLOCK Request Body. RuleID=%d URI=%s", it.RuleID, r.RequestURI)
					log.Print(logMessage) // 打印到控制台
					if wm.auditLogger != nil {
						wm.auditLogger.Println(logMessage) // 写入到 waf_audit.log
					}
					w.WriteHeader(it.Status)
					return
				}
			}
		}

		// 4️⃣ 自定义 ResponseWriter 捕获响应
		crw := &CustomResponseWriter{
			ResponseWriter: w,
			Body:           new(bytes.Buffer),
			StatusCode:     http.StatusOK,
		}

		// 调用下一个 handler
		next.ServeHTTP(crw, r)

		// 5️⃣ 处理响应头
		for k, vv := range crw.Header() {
			for _, v := range vv {
				tx.AddResponseHeader(k, v)
			}
		}
		if it := tx.ProcessResponseHeaders(crw.StatusCode, r.Proto); it != nil {
			logMessage := fmt.Sprintf("[WAFManager] BLOCK Response Headers. RuleID=%d URI=%s", it.RuleID, r.RequestURI)
			log.Print(logMessage) // 打印到控制台
			if wm.auditLogger != nil {
				wm.auditLogger.Println(logMessage) // 写入到 waf_audit.log
			}
			return
		}

		// 6️⃣ 处理响应体
		if _, _, err := tx.WriteResponseBody(crw.Body.Bytes()); err != nil {
			logMessage := fmt.Sprintf("[WAFManager] Error writing response body: %v", err)
			log.Print(logMessage)
			if wm.auditLogger != nil {
				wm.auditLogger.Print(logMessage)
			}
			return
		}
		if it, err := tx.ProcessResponseBody(); err != nil || it != nil {
			if it != nil {
				logMessage := fmt.Sprintf("[WAFManager] BLOCK Response Body. RuleID=%d URI=%s", it.RuleID, r.RequestURI)
				log.Print(logMessage) // 打印到控制台
				if wm.auditLogger != nil {
					wm.auditLogger.Println(logMessage) // 写入到 waf_audit.log
				}
			}
			return
		}
	})
}

// CustomResponseWriter 用于捕获响应 body
type CustomResponseWriter struct {
	http.ResponseWriter
	Body       *bytes.Buffer
	StatusCode int
}

func (w *CustomResponseWriter) Write(b []byte) (int, error) {
	w.Body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *CustomResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// generateSimpleRule 将简化的规则定义转换为 Coraza 规则字符串
// 注意：此函数是一个示例，用于演示如何在后端处理这些规则。
// 在实际应用中，您需要将其集成到您的 API 逻辑中。
func generateSimpleRule(ruleType, path string, limit, window, ruleId int) string {
	// 将通配符 * 转换为 PCRE 正则表达式 .*
	regexPath := strings.ReplaceAll(path, "*", ".*")

	switch ruleType {
	case "directory":
		// 使用 @beginsWith 操作符来匹配目录前缀
		// 为了更精确，可以确保它以 / 结尾或匹配整个路径段
		startsWith_path := strings.TrimSuffix(path, "*")
		return fmt.Sprintf(
			`SecRule REQUEST_URI "@beginsWith %s" "id:%d,phase:1,deny,status:403,log,msg:'Directory access denied: %s'"`,
			startsWith_path, ruleId, path,
		)
	case "file":
		// 使用 @rx 操作符和转换后的正则表达式来匹配文件名/路径
		return fmt.Sprintf(
			`SecRule REQUEST_FILENAME "@rx %s" "id:%d,phase:1,deny,status:403,log,msg:'File access denied: %s'"`,
			regexPath, ruleId, path,
		)
	case "ratelimit":
		// Coraza 的速率限制比较复杂，这只是一个非常简化的示例
		// 实际上，您可能需要使用 ip.ratelimit 集合和更复杂的逻辑
		// 这里仅为演示目的
		return fmt.Sprintf(
			`SecRule IP:RATELIMIT "@gt %d" "id:%d,phase:1,deny,status:429,log,msg:'Rate limit of %d req/%ds exceeded for %s'"`,
			limit, ruleId, limit, window, path,
		)
	}
	return ""
}

// GetRuleSetRules retrieves the rules for a given rule set name, fetching from source if necessary.
func (wm *WAFManager) GetRuleSetRules(name string) ([]string, error) {
	configMutex.RLock()
	defer configMutex.RUnlock()

	var ruleSet *WAFRuleSet
	for i := range currentConfig.WAF.RuleSets {
		if currentConfig.WAF.RuleSets[i].Name == name {
			ruleSet = &currentConfig.WAF.RuleSets[i]
			break
		}
	}

	if ruleSet == nil {
		return nil, fmt.Errorf("rule set '%s' not found", name)
	}

	var rawRules []byte
	var err error

	switch ruleSet.Source {
	case "inline":
		return ruleSet.Rules, nil
	case "url":
		if ruleSet.Path == "" {
			return nil, fmt.Errorf("URL source for rule set '%s' is empty", name)
		}
		resp, err := http.Get(ruleSet.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch rules from URL %s: %v", ruleSet.Path, err)
		}
		defer resp.Body.Close()
		rawRules, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body from URL %s: %v", ruleSet.Path, err)
		}
	case "file":
		if ruleSet.Path == "" {
			return nil, fmt.Errorf("file source for rule set '%s' is empty", name)
		}
		rawRules, err = ioutil.ReadFile(ruleSet.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read rules from file %s: %v", ruleSet.Path, err)
		}
	default:
		return nil, fmt.Errorf("unsupported rule source '%s' for rule set '%s'", ruleSet.Source, name)
	}

	// Split rules by newline, filtering out empty lines or carriage returns
	rules := strings.Split(string(rawRules), "\n")
	var cleanedRules []string
	for _, r := range rules {
		cleanedR := strings.TrimSpace(r)
		if cleanedR != "" {
			cleanedRules = append(cleanedRules, cleanedR)
		}
	}
	return cleanedRules, nil
}