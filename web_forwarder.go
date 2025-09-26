package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/time/rate"
)

// contextKey is a private type to prevent collisions in context keys.
type contextKey string

const connContextKey = contextKey("netConn")
const subRuleContextKey = contextKey("subRule")

// --- Rate Limiting Wrappers for HTTP ---

// rateLimitedResponseWriter wraps http.ResponseWriter to limit response writing speed.
type rateLimitedResponseWriter struct {
	http.ResponseWriter
	writer io.Writer
}

func (w *rateLimitedResponseWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

// rateLimitedRequestBody wraps io.ReadCloser to limit request body reading speed.
type rateLimitedRequestBody struct {
	io.ReadCloser
	reader io.Reader
}

func (r *rateLimitedRequestBody) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func authMiddleware(next http.Handler, authConfig WebSubRuleAuth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authConfig.Enabled {
			user, pass, ok := r.BasicAuth()
			if !ok || user != authConfig.Username || pass != authConfig.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// applyLimitsMiddleware is an HTTP middleware that applies rate limits and connection limits to a request.
func applyLimitsMiddleware(next http.Handler, subRule WebSubRule, mainRule WebServiceRule, ipConnLimiter *IPConnectionLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]

		// Sub-rule IP Connection Limit Check
		if !mainRule.ApplyToSubRules {
			limit := subRule.Limits.IPConnectionLimit
			if limit > 0 {
				if !ipConnLimiter.Check(mainRule.Name, clientIP, limit) {
					log.Printf("[%s %s] 拒绝来自 %s 的连接: 已达到子规则IP连接数限制 (%d)", mainRule.Name, subRule.Name, clientIP, limit)
					if hj, ok := w.(http.Hijacker); ok {
						conn, _, err := hj.Hijack()
						if err == nil {
							conn.Close()
							return
						}
					}
					http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
					return
				}
			}
		}

		// Determine which rate limits to apply (sub-rule overrides main rule if not inherited)
		sendLimit := mainRule.Limits.ConnectionRateLimit.SendSpeedKBps
		recvLimit := mainRule.Limits.ConnectionRateLimit.ReceiveSpeedKBps

		if !mainRule.ApplyToSubRules {
			if subRule.Limits.ConnectionRateLimit.SendSpeedKBps > 0 {
				sendLimit = subRule.Limits.ConnectionRateLimit.SendSpeedKBps
			}
			if subRule.Limits.ConnectionRateLimit.ReceiveSpeedKBps > 0 {
				recvLimit = subRule.Limits.ConnectionRateLimit.ReceiveSpeedKBps
			}
		}

		// Wrap ResponseWriter for send speed limiting
		if sendLimit > 0 {
			limiter := rate.NewLimiter(rate.Limit(sendLimit*1024), sendLimit*1024)
			w = &rateLimitedResponseWriter{
				ResponseWriter: w,
				writer:         &rateLimitedWriter{w: w, limiter: limiter},
			}
		}

		// Wrap Request.Body for receive speed limiting
		if recvLimit > 0 {
			limiter := rate.NewLimiter(rate.Limit(recvLimit*1024), recvLimit*1024)
			r.Body = &rateLimitedRequestBody{
				ReadCloser: r.Body,
				reader:     &rateLimitedReader{r: r.Body, limiter: limiter},
			}
		}

		next.ServeHTTP(w, r)
	})
}

// loggingTransport is a custom http.RoundTripper that logs requests and responses.
type loggingTransport struct {
	Transport http.RoundTripper
	RuleName  string
}

// RoundTrip executes a single HTTP transaction, adding logging around the core operation.
func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	logRuleName := t.RuleName
	if sub, ok := req.Context().Value(subRuleContextKey).(WebSubRule); ok {
		logRuleName = fmt.Sprintf("%s %s", t.RuleName, sub.Name)
	}

	log.Printf("[%s] 正在转发请求: %s %s -> %s", logRuleName, req.Method, req.Host, req.URL)

	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		log.Printf("[%s] 后端连接错误: %v", logRuleName, err)
	} else {
		log.Printf("[%s] 收到后端响应: %s", logRuleName, resp.Status)
	}
	return resp, err
}

func autoAppendZone(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || !ip.IsLinkLocalUnicast() {
		return addr
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[WebForwarder] 无法获取网络接口列表来解析链路本地地址: %v", err)
		return addr
	}

	var foundInterfaces []string
	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				foundInterfaces = append(foundInterfaces, i.Name)
			}
		}
	}

	if len(foundInterfaces) == 1 {
		log.Printf("[WebForwarder] 已自动为地址 [%s] 找到网络接口 [%s]", addr, foundInterfaces[0])
		return fmt.Sprintf("%s%%%s", addr, foundInterfaces[0])
	}

	if len(foundInterfaces) > 1 {
		log.Printf("[WebForwarder] 错误: 链路本地地址 [%s] 存在于多个网络接口上 (%v)。请在配置中明确指定区域索引，例如: '%s%%%s'", addr, foundInterfaces, addr, foundInterfaces[0])
	} else {
		log.Printf("[WebForwarder] 错误: 无法在任何网络接口上找到链路本地地址 [%s]", addr)
	}

	return addr
}

func buildTLSConfig(tlsConfig WebTLSConfig) *tls.Config {
	cfg := &tls.Config{}

	switch tlsConfig.MinVersion {
	case "TLS1.0":
		cfg.MinVersion = tls.VersionTLS10
	case "TLS1.1":
		cfg.MinVersion = tls.VersionTLS11
	case "TLS1.3":
		cfg.MinVersion = tls.VersionTLS13
	default:
		cfg.MinVersion = tls.VersionTLS12
	}

	if tlsConfig.HTTP3Enabled {
		cfg.NextProtos = []string{"h3", "h2", "http/1.1"}
	} else {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}

	if tlsConfig.ECHEnabled {
		log.Printf("[WebForwarder] 警告: ECH (Encrypted Client Hello) 是一个实验性功能，当前版本尚未支持。")
	}

	return cfg
}

// WebForwarder represents an individual, runnable web service instance.
type WebForwarder struct {
	rule          WebServiceRule
	ipFilter      *IPFilterManager
	connManager   *ConnectionManager
	ipConnLimiter *IPConnectionLimiter
	hostToSubRule map[string]WebSubRule
	wafManager    *WAFManager
}

func NewWebForwarder(rule WebServiceRule, ipFilter *IPFilterManager, connManager *ConnectionManager, ipConnLimiter *IPConnectionLimiter, wafManager *WAFManager) (*WebForwarder, error) {
	return &WebForwarder{
		rule:          rule,
		ipFilter:      ipFilter,
		connManager:   connManager,
		ipConnLimiter: ipConnLimiter,
		hostToSubRule: make(map[string]WebSubRule),
		wafManager:    wafManager,
	}, nil
}


// Start boots up the HTTP/HTTPS server(s) based on the rule configuration.
func (wf *WebForwarder) Start() []*http.Server {
	hostHandlers := make(map[string]http.Handler)

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

			transport := &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: subRule.Backend.IgnoreTLSCert},
				DisableKeepAlives:     subRule.Network.DisableConnectionReuse,
			}

			proxy.Transport = &loggingTransport{
				Transport: transport,
				RuleName:  wf.rule.Name,
			}

			director := proxy.Director
			proxy.Director = func(req *http.Request) {
				director(req)
				if subRule.Backend.UseTargetHostHeader {
					req.Host = target.Host
				}

				subRule, ok := req.Context().Value(subRuleContextKey).(WebSubRule)
				if !ok {
					return
				}

				clientIP := req.RemoteAddr
				if subRule.ClientIP.FromHeader {
					if headerIP := req.Header.Get(subRule.ClientIP.FromHeaderName); headerIP != "" {
						clientIP = headerIP
					}
				}
				clientIP, _, _ = net.SplitHostPort(clientIP)

				if subRule.ForwardedHeaders.Enabled {
					req.Header.Set("X-Real-IP", clientIP)

					if prior, ok := req.Header["X-Forwarded-For"]; ok {
						req.Header.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+clientIP)
					} else {
						req.Header.Set("X-Forwarded-For", clientIP)
					}

					proto := "http"
					if req.TLS != nil {
						proto = "https"
					}
					req.Header.Set("X-Forwarded-Proto", proto)
					req.Header.Set("X-Real-Proto", proto)

					req.Header.Set("X-Forwarded-Host", req.Host)

					_, port, err := net.SplitHostPort(req.Host)
					if err != nil {
						if req.TLS != nil {
							port = "443"
						} else {
							port = "80"
						}
					}
					req.Header.Set("X-Forwarded-Port", port)
				}
			}

			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("[%s %s] Web代理发生严重错误: %v", wf.rule.Name, subRule.Name, err)
				w.WriteHeader(http.StatusBadGateway)
			}
			handler = applyLimitsMiddleware(proxy, subRule, wf.rule, wf.ipConnLimiter)

		case "redirect":
			handler = http.RedirectHandler(subRule.RedirectURL, http.StatusMovedPermanently)

		default:
			log.Printf("[WebForwarder] 规则 [%s] 的子规则 [%s] 服务类型未知: %s", wf.rule.Name, subRule.Name, subRule.ServiceType)
			continue
		}
		if subRule.CorazaWAF != "无" && subRule.CorazaWAF != "" {
			handler = wf.wafManager.Middleware(handler, subRule.CorazaWAF)
		}

		hostHandlers[subRule.FrontendAddress] = authMiddleware(handler, subRule.Auth)
		wf.hostToSubRule[subRule.FrontendAddress] = subRule
	}

	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientAddrWithPort := r.RemoteAddr
		clientIP := strings.Split(clientAddrWithPort, ":")[0]
		host := strings.Split(r.Host, ":")[0]

		if handler, ok := hostHandlers[host]; ok {
			subRule := wf.hostToSubRule[host]
			logRuleName := fmt.Sprintf("%s %s", wf.rule.Name, subRule.Name)

			if wf.rule.AccessControl.Mode != "disabled" {
				allowed, reason := wf.ipFilter.IsAllowed(clientIP, wf.rule.AccessControl)
				if !allowed {
					log.Printf("[%s] 拒绝请求 (主规则): %s (%s)", wf.rule.Name, clientAddrWithPort, reason)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			if subRule.IPFilter.Mode != "disabled" {
				allowed, reason := wf.ipFilter.IsAllowed(clientIP, subRule.IPFilter)
				if !allowed {
					log.Printf("[%s] 拒绝请求 (子规则): %s (%s)", logRuleName, clientAddrWithPort, reason)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			if subRule.CORSEnabled {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				if r.Method == "OPTIONS" {
					w.WriteHeader(http.StatusOK)
					return
				}
			}

			ctx := context.WithValue(r.Context(), subRuleContextKey, subRule)
			if subRule.ForceHTTPS && r.TLS == nil {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
				return
			}

			log.Printf("[%s] 处理请求: %s -> %s %s", logRuleName, clientAddrWithPort, r.Method, r.Host+r.RequestURI)
			if conn, ok := r.Context().Value(connContextKey).(net.Conn); ok {
				wf.connManager.UpdateSubRuleForConn(conn, subRule.Name, subRule.FrontendAddress)
			}
			handler.ServeHTTP(w, r.WithContext(ctx))

		} else {
			log.Printf("[%s] 请求未匹配子规则: %s -> %s %s", wf.rule.Name, clientAddrWithPort, r.Method, r.Host+r.RequestURI)

			if conn, ok := r.Context().Value(connContextKey).(net.Conn); ok {
				wf.connManager.UpdateSubRuleForConn(conn, "未匹配", "未匹配")
			}

			switch wf.rule.UnmatchedRequest.Action {
			case "close":
				if hj, ok := w.(http.Hijacker); ok {
					conn, _, err := hj.Hijack()
					if err == nil {
						conn.Close()
					}
				}
			case "proxy":
				target, err := url.Parse(wf.rule.UnmatchedRequest.ProxyAddress)
				if err != nil {
					log.Printf("[%s] 未匹配请求的代理地址无效: %v", wf.rule.Name, err)
					http.Error(w, "Bad Gateway", http.StatusBadGateway)
					return
				}
				proxy := httputil.NewSingleHostReverseProxy(target)
				handler := applyLimitsMiddleware(proxy, WebSubRule{}, wf.rule, wf.ipConnLimiter)
				handler.ServeHTTP(w, r)
			case "redirect":
				http.Redirect(w, r, wf.rule.UnmatchedRequest.RedirectURL, http.StatusFound)
			case "static_text":
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Write([]byte(wf.rule.UnmatchedRequest.StaticText))
			default:
				http.Error(w, "Not Found", http.StatusNotFound)
			}
		}
	})

	var servers []*http.Server

	startServer := func(network, listenAddr string) (*http.Server, error) {
		server := &http.Server{
			Addr:              listenAddr,
			Handler:           mainHandler,
			ReadHeaderTimeout: 15 * time.Second,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				clientIP := strings.Split(c.RemoteAddr().String(), ":")[0]
				limit := wf.rule.Limits.IPConnectionLimit

				if limit > 0 && !wf.ipConnLimiter.Check(wf.rule.Name, clientIP, limit) {
					log.Printf("[%s] 拒绝来自 %s 的新连接: 已达到主规则IP连接数限制 (%d)", wf.rule.Name, clientIP, limit)
					c.Close()
					ctx, cancel := context.WithCancel(ctx)
					cancel()
					return ctx
				}

				return context.WithValue(ctx, connContextKey, c)
			},
			ConnState: func(conn net.Conn, state http.ConnState) {
				clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
				ruleName := wf.rule.Name
				switch state {
				case http.StateNew:
					wf.connManager.AddHTTPConn(conn, ruleName, "")
					wf.ipConnLimiter.Increment(ruleName, clientIP)
				case http.StateClosed, http.StateHijacked:
					wf.connManager.RemoveByConn(conn)
					wf.ipConnLimiter.Decrement(ruleName, clientIP)
				}
			},
		}

		var err error
		if wf.rule.TLS.Enabled {
			server.TLSConfig, err = certManager.GetTLSConfig()
			if err != nil {
				log.Printf("[WebForwarder] 规则 [%s] 获取TLS配置失败: %v", wf.rule.Name, err)
				return nil, err
			}

			ruleTLSConfig := buildTLSConfig(wf.rule.TLS)
			server.TLSConfig.MinVersion = ruleTLSConfig.MinVersion
			server.TLSConfig.NextProtos = ruleTLSConfig.NextProtos
		}

		lc := getListenConfig()

		if wf.rule.TLS.Enabled {
			if wf.rule.TLS.HTTP3Enabled {
				log.Printf("==== Web 服务 [%s] 正在启动并尝试监听在 %s (HTTP/3) ====", wf.rule.Name, listenAddr)
				h3Server := &http3.Server{
					Addr:      server.Addr,
					Handler:   server.Handler,
					TLSConfig: server.TLSConfig,
				}
				go func() {
					if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						log.Printf("[WebForwarder] Web服务 [%s] 在 [%s] (HTTP/3) 发生错误: %v", wf.rule.Name, listenAddr, err)
					}
				}()
			} else {
				listener, listenErr := lc.Listen(context.Background(), network, listenAddr)
				if listenErr != nil {
					err = fmt.Errorf("[WebForwarder] 规则 [%s] 在 [%s] 监听失败: %v", wf.rule.Name, listenAddr, listenErr)
					log.Println(err)
					return nil, err
				}

				log.Printf("==== Web 服务 [%s] 已启动并成功监听在 %s (HTTPS) ====", wf.rule.Name, listenAddr)
				go func() {
					if err := server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
						log.Printf("[WebForwarder] Web服务 [%s] 在 [%s] (HTTPS) 发生错误: %v", wf.rule.Name, listenAddr, err)
					}
				}()
			}
		} else {
			listener, listenErr := lc.Listen(context.Background(), network, listenAddr)
			if listenErr != nil {
				err = fmt.Errorf("[WebForwarder] 规则 [%s] 在 [%s] 监听失败: %v", wf.rule.Name, listenAddr, listenErr)
				log.Println(err)
				return nil, err
			}

			log.Printf("==== Web 服务 [%s] 已启动并成功监听在 %s (HTTP) ====", wf.rule.Name, listenAddr)
			go func() {
				if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
					log.Printf("[WebForwarder] Web服务 [%s] 在 [%s] (HTTP) 发生错误: %v", wf.rule.Name, listenAddr, err)
				}
			}()
		}
		return server, nil
	}

	if wf.rule.ListenAddr != "" {
		addrWithZone := autoAppendZone(wf.rule.ListenAddr)
		addr := net.JoinHostPort(addrWithZone, strconv.Itoa(wf.rule.ListenPort))

		network := "tcp"
		if wf.rule.TLS.Enabled && wf.rule.TLS.HTTP3Enabled {
			network = "udp"
		}
		if s, err := startServer(network, addr); err == nil {
			servers = append(servers, s)
		}
	} else {
		if wf.rule.ListenIPv4 {
			addr := fmt.Sprintf("0.0.0.0:%d", wf.rule.ListenPort)
			network := "tcp4"
			if wf.rule.TLS.Enabled && wf.rule.TLS.HTTP3Enabled {
				network = "udp4"
			}
			if s, err := startServer(network, addr); err == nil {
				servers = append(servers, s)
			}
		}
		if wf.rule.ListenIPv6 {
			addr := fmt.Sprintf("[::]:%d", wf.rule.ListenPort)
			network := "tcp6"
			if wf.rule.TLS.Enabled && wf.rule.TLS.HTTP3Enabled {
				network = "udp6"
			}
			if s, err := startServer(network, addr); err == nil {
				servers = append(servers, s)
			}
		}
	}

	return servers
}