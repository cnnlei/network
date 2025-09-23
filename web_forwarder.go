package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// contextKey is a private type to prevent collisions in context keys.
type contextKey string

const connContextKey = contextKey("netConn")
const subRuleContextKey = contextKey("subRule")

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
	rule        WebServiceRule
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

// Start boots up the HTTP/HTTPS server(s) based on the rule configuration.
func (wf *WebForwarder) Start() []*http.Server {
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

			proxy.Transport = &loggingTransport{
				Transport: http.DefaultTransport,
				RuleName:  wf.rule.Name,
			}

			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("[%s %s] Web代理发生严重错误: %v", wf.rule.Name, subRule.Name, err)
				w.WriteHeader(http.StatusBadGateway)
			}
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
		clientAddrWithPort := r.RemoteAddr

		if wf.rule.AccessControl.Mode != "disabled" {
			clientIP := strings.Split(clientAddrWithPort, ":")[0]
			allowed, reason := wf.ipFilter.IsAllowed(clientIP, wf.rule.AccessControl)
			if !allowed {
				log.Printf("[%s] 拒绝请求: %s (%s)", wf.rule.Name, clientAddrWithPort, reason)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		host := strings.Split(r.Host, ":")[0]
		if handler, ok := hostHandlers[host]; ok {
			subRule := hostToSubRule[host]
			ctx := context.WithValue(r.Context(), subRuleContextKey, subRule)

			if subRule.ForceHTTPS && r.TLS == nil {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
				return
			}

			logRuleName := fmt.Sprintf("%s %s", wf.rule.Name, subRule.Name)
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

			http.Error(w, "Not Found", http.StatusNotFound)
		}
	})

	var servers []*http.Server

	startServer := func(network, listenAddr string) *http.Server {
		server := &http.Server{
			Addr:              listenAddr,
			Handler:           mainHandler,
			ReadHeaderTimeout: 15 * time.Second,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connContextKey, c)
			},
			ConnState: func(conn net.Conn, state http.ConnState) {
				switch state {
				case http.StateNew:
					log.Printf("[%s] 新的Web连接: %s on %s", wf.rule.Name, conn.RemoteAddr().String(), conn.LocalAddr().String())
					wf.connManager.AddHTTPConn(conn, wf.rule.Name, "")
				case http.StateClosed, http.StateHijacked:
					wf.connManager.RemoveByConn(conn)
				}
			},
		}

		if wf.rule.TLS.Enabled {
			server.TLSConfig = buildTLSConfig(wf.rule.TLS)
		}

		go func() {
			var err error
			if wf.rule.TLS.Enabled {
				certFile := "cert.pem"
				keyFile := "key.pem"
				if _, errStat := os.Stat(certFile); os.IsNotExist(errStat) {
					log.Printf("[WebForwarder] 错误: 规则 [%s] 启用了TLS，但未找到 %s 或 %s。", wf.rule.Name, certFile, keyFile)
					return
				}

				if wf.rule.TLS.HTTP3Enabled {
					log.Printf("[WebForwarder] 规则 [%s] 以HTTPS + HTTP/3模式启动。", wf.rule.Name)
					h3Server := &http3.Server{
						Addr:      server.Addr,
						Handler:   server.Handler,
						TLSConfig: server.TLSConfig,
					}
					err = h3Server.ListenAndServeTLS(certFile, keyFile)
				} else {
					lc := net.ListenConfig{
						Control: func(network, address string, c syscall.RawConn) error {
							var err error
							if strings.HasPrefix(network, "tcp6") {
								err = c.Control(func(fd uintptr) {
									err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
								})
							}
							return err
						},
					}
					listener, listenErr := lc.Listen(context.Background(), network, listenAddr)
					if listenErr != nil {
						log.Printf("[WebForwarder] 规则 [%s] 在 [%s] 监听失败: %v", wf.rule.Name, listenAddr, listenErr)
						return
					}
					log.Printf("[WebForwarder] 规则 [%s] 以HTTPS (HTTP/2, HTTP/1.1)模式启动。", wf.rule.Name)
					err = server.ServeTLS(listener, certFile, keyFile)
				}
			} else {
				listener, listenErr := net.Listen(network, listenAddr)
				if listenErr != nil {
					log.Printf("[WebForwarder] 规则 [%s] 在 [%s] 监听失败: %v", wf.rule.Name, listenAddr, listenErr)
					return
				}
				err = server.Serve(listener)
			}

			if err != nil && err != http.ErrServerClosed {
				log.Printf("[WebForwarder] Web服务 [%s] 在 [%s] 发生错误: %v", wf.rule.Name, listenAddr, err)
			}
		}()
		return server
	}

	if wf.rule.ListenAddr != "" {
		addrWithZone := autoAppendZone(wf.rule.ListenAddr)
		addr := net.JoinHostPort(addrWithZone, strconv.Itoa(wf.rule.ListenPort))
		
		network := "tcp"
		if wf.rule.TLS.Enabled && wf.rule.TLS.HTTP3Enabled {
			network = "udp"
		}
		if s := startServer(network, addr); s != nil {
			servers = append(servers, s)
		}
	} else {
		if wf.rule.ListenIPv4 {
			addr := fmt.Sprintf("0.0.0.0:%d", wf.rule.ListenPort)
			network := "tcp4"
			if wf.rule.TLS.Enabled && wf.rule.TLS.HTTP3Enabled {
				network = "udp4"
			}
			if s := startServer(network, addr); s != nil {
				servers = append(servers, s)
			}
		}
		if wf.rule.ListenIPv6 {
			addr := fmt.Sprintf("[::]:%d", wf.rule.ListenPort)
			network := "tcp6"
			if wf.rule.TLS.Enabled && wf.rule.TLS.HTTP3Enabled {
				network = "udp6"
			}
			if s := startServer(network, addr); s != nil {
				servers = append(servers, s)
			}
		}
	}

	return servers
}