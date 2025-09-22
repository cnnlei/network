package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// WebForwarder 代表一个独立的、可运行的Web服务实例
type WebForwarder struct {
	rule        WebServiceRule
	server      *http.Server
	ipFilter    *IPFilterManager
	connManager *ConnectionManager
}

func NewWebForwarder(rule WebServiceRule, ipFilter *IPFilterManager, connManager *ConnectionManager) (*WebForwarder, error) {
	return &WebForwarder{
		rule:        rule,
		ipFilter:    ipFilter,
		connManager: connManager,
	}, nil
}

// --- 日志中间件 ---
func loggingMiddleware(ruleName string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := strings.Split(r.RemoteAddr, ":")[0]
        
        // 从 context 中获取子规则名称
        logRuleName := ruleName
        if subRule, ok := r.Context().Value("subRule").(WebSubRule); ok {
            logRuleName = fmt.Sprintf("%s %s", ruleName, subRule.Name)
        }

        log.Printf("[%s] Web请求: %s -> %s %s", logRuleName, clientIP, r.Method, r.Host+r.RequestURI)
        
        next.ServeHTTP(w, r)
    })
}

// Start 启动HTTP/HTTPS服务器
func (wf *WebForwarder) Start() *http.Server {
	hostHandlers := make(map[string]http.Handler)
    hostToSubRule := make(map[string]WebSubRule)

	for _, subRule := range wf.rule.SubRules {
		if !subRule.Enabled {
			continue
		}

		var handler http.Handler
		switch subRule.ServiceType {
		case "reverse_proxy":
			target, err := url.Parse(subRule.Backend.Address)
			if err != nil {
				log.Printf("[WebForwarder] 规则 [%s] 的子规则 [%s] 后端地址无效: %v", wf.rule.Name, subRule.Name, err)
				continue
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			handler = proxy

		case "redirect":
			handler = http.RedirectHandler(subRule.RedirectURL, http.StatusMovedPermanently)
		
		default:
			log.Printf("[WebForwarder] 规则 [%s] 的子规则 [%s] 服务类型未知: %s", wf.rule.Name, subRule.Name, subRule.ServiceType)
			continue
		}

		hostHandlers[subRule.FrontendAddress] = handler
        hostToSubRule[subRule.FrontendAddress] = subRule
	}
	
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		
		if wf.rule.AccessControl.Mode != "disabled" {
			allowed, reason := wf.ipFilter.IsAllowed(clientIP, wf.rule.AccessControl)
			if !allowed {
				log.Printf("[WebForwarder] 规则 [%s] 拒绝了来自 %s 的请求: %s", wf.rule.Name, clientIP, reason)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
        
        if wf.rule.TLS.Enabled && wf.rule.TLS.ForceHTTPS && r.TLS == nil {
            target := "https://" + r.Host + r.URL.Path
            if len(r.URL.RawQuery) > 0 {
                target += "?" + r.URL.RawQuery
            }
            http.Redirect(w, r, target, http.StatusPermanentRedirect)
            return
        }

		host := strings.Split(r.Host, ":")[0]
		if handler, ok := hostHandlers[host]; ok {
            subRule := hostToSubRule[host]
            ctx := context.WithValue(r.Context(), "subRule", subRule)
			handler.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	})

	listenAddr := fmt.Sprintf("%s:%d", wf.rule.ListenAddr, wf.rule.ListenPort)
	wf.server = &http.Server{
		Addr:    listenAddr,
		Handler: loggingMiddleware(wf.rule.Name, mainHandler),
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
                // 注意：在StateNew阶段，我们还不知道请求的Host，所以子规则名暂时为空
				wf.connManager.AddHTTPConn(conn, wf.rule.Name, "")
			case http.StateClosed, http.StateHijacked:
				wf.connManager.RemoveByConn(conn)
			}
		},
	}

	go func() {
		log.Printf("[WebForwarder] 开始监听Web服务 [%s] on %s", wf.rule.Name, listenAddr)
		var err error
		if wf.rule.TLS.Enabled {
			certFile := "cert.pem"
			keyFile := "key.pem"
			if _, errStat := os.Stat(certFile); os.IsNotExist(errStat) {
				log.Printf("[WebForwarder] 警告: 规则 [%s] 启用了TLS，但未找到 %s。服务将以HTTP模式启动。", wf.rule.Name, certFile)
				err = wf.server.ListenAndServe()
			} else {
				log.Printf("[WebForwarder] 规则 [%s] 以HTTPS模式启动。", wf.rule.Name)
				err = wf.server.ListenAndServeTLS(certFile, keyFile)
			}
		} else {
			err = wf.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Printf("[WebForwarder] Web服务 [%s] 启动失败: %v", wf.rule.Name, err)
		}
	}()
    
    return wf.server
}

// Shutdown 平滑地关闭服务器
func (wf *WebForwarder) Shutdown() {
	if wf.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		wf.server.Shutdown(ctx)
	}
}