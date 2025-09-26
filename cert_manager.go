package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// CertificateInfo 用于向前端传递证书的详细信息
type CertificateInfo struct {
	Domain     string    `json:"Domain"`
	Type       string    `json:"Type"` // "Manual" or "ACME"
	Status     string    `json:"Status"` // "Issued", "Not Issued", "Parse Failed"
	Issuer     string    `json:"Issuer"`
	NotAfter   time.Time `json:"NotAfter"` // 证书到期时间
	DaysLeft   int       `json:"DaysLeft"`
	IsStaging  bool      `json:"IsStaging"`
	FilePath   string    `json:"FilePath"`
	Account    string    `json:"Account,omitempty"` // 显示所使用的ACME账户
}

// CertManager 负责管理所有TLS证书
type CertManager struct {
	mu            sync.RWMutex
	tlsConfig     *TLSConfig
	certCache     map[string]*tls.Certificate
	certDirectory string
}

// NewCertManager 创建一个新的 CertManager 实例
func NewCertManager(cfg *TLSConfig) (*CertManager, error) {
	certDir := "certs"
	if cfg.CertDirectory != "" {
		certDir = cfg.CertDirectory
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return nil, fmt.Errorf("无法创建证书目录 %s: %w", certDir, err)
	}

	manager := &CertManager{
		tlsConfig:     cfg,
		certCache:     make(map[string]*tls.Certificate),
		certDirectory: certDir,
	}

	go manager.startRenewalChecker()

	return manager, nil
}

// UpdateTLSConfig 用于热重载 TLS 配置，无需重启服务
func (m *CertManager) UpdateTLSConfig(newConfig *TLSConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tlsConfig = newConfig
	m.certCache = make(map[string]*tls.Certificate) // 清空缓存以重新加载
	log.Println("[CertManager] TLS 配置已热重载。")
}

// GetTLSConfig 为 Web 服务器生成一个 tls.Config
func (m *CertManager) GetTLSConfig() (*tls.Config, error) {
	m.mu.RLock()
	isEnabled := m.tlsConfig.Enabled
	m.mu.RUnlock()

	if !isEnabled {
		return nil, nil
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := m.getCertificate(hello.ServerName)
			if err != nil {
				log.Printf("[CertManager] 未能为域 %s 提供证书: %v", hello.ServerName, err)
				return nil, err
			}
			return cert, nil
		},
	}
	return config, nil
}

// getCertificate 是 tls.Config 的 GetCertificate 回调函数
func (m *CertManager) getCertificate(domain string) (*tls.Certificate, error) {
	m.mu.RLock()
	// 1. 检查缓存
	cert, found := m.certCache[domain]
	if found {
		return cert, nil
	}
	currentTlsConfig := m.tlsConfig
	m.mu.RUnlock()

	// 2. 查找手动配置的证书
	for _, manualCert := range currentTlsConfig.Manual {
		for _, d := range manualCert.Domains {
			if d == domain {
				log.Printf("[CertManager] 正在为域 %s 加载手动指定的证书", domain)
				newCert, err := tls.LoadX509KeyPair(manualCert.CertPath, manualCert.KeyPath)
				if err != nil {
					return nil, fmt.Errorf("加载手动证书失败 (%s): %w", domain, err)
				}
				m.cacheCertificate(domain, &newCert)
				return &newCert, nil
			}
		}
	}

	// 3. 查找ACME证书
	certPath := filepath.Join(m.certDirectory, domain, "fullchain.pem")
	keyPath := filepath.Join(m.certDirectory, domain, "privkey.pem")

	if _, err := os.Stat(certPath); err == nil {
		newCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("为域 %s 加载ACME磁盘证书失败: %w", domain, err)
		}
		m.cacheCertificate(domain, &newCert)
		log.Printf("[CertManager] 已为域 %s 从磁盘加载ACME证书", domain)
		return &newCert, nil
	}

	return nil, fmt.Errorf("未找到域 %s 的任何手动或ACME证书", domain)
}

// cacheCertificate 将证书存入缓存
func (m *CertManager) cacheCertificate(domain string, cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache[domain] = cert
}

// startRenewalChecker 启动一个后台任务，定期检查ACME证书是否需要续订
func (m *CertManager) startRenewalChecker() {
	log.Println("[CertManager] ACME 证书自动续订检查服务已启动")
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		m.checkAndRenewAll()
		<-ticker.C
	}
}

// checkAndRenewAll 检查所有配置的ACME域并尝试续订
func (m *CertManager) checkAndRenewAll() {
	m.mu.RLock()
	currentTlsConfig := m.tlsConfig
	m.mu.RUnlock()

	if !currentTlsConfig.ACME.Enabled {
		return
	}
	log.Println("[CertManager] 开始每日证书续订检查...")
	for _, account := range currentTlsConfig.ACME.Accounts {
		for _, domain := range account.Domains {
			certPath := filepath.Join(m.certDirectory, domain, "fullchain.pem")
			if _, err := os.Stat(certPath); os.IsNotExist(err) {
				log.Printf("[CertManager] 域 %s 证书不存在，将尝试获取新证书 (使用账户: %s)", domain, account.Name)
				go m.RequestCertificate(domain)
				continue
			}

			certBytes, err := os.ReadFile(certPath)
			if err != nil {
				log.Printf("[CertManager] 无法读取证书文件 %s: %v", certPath, err)
				continue
			}

			certs, err := certcrypto.ParsePEMBundle(certBytes)
			if err != nil || len(certs) == 0 {
				log.Printf("[CertManager] 解析证书文件 %s 失败: %v", certPath, err)
				continue
			}

			if time.Until(certs[0].NotAfter) < 30*24*time.Hour {
				log.Printf("[CertManager] 域 %s 的证书即将在30天内到期，开始续订 (使用账户: %s)", domain, account.Name)
				go m.RequestCertificate(domain)
			} else {
				log.Printf("[CertManager] 域 %s 的证书仍然有效", domain)
			}
		}
	}
}

// RequestCertificate 使用ACME为指定域请求新证书
func (m *CertManager) RequestCertificate(domain string) error {
	m.mu.RLock()
	currentTlsConfig := m.tlsConfig
	m.mu.RUnlock()

	acmeConfig := currentTlsConfig.ACME
	if !acmeConfig.Enabled {
		return fmt.Errorf("ACME 未启用")
	}

	var targetAccount *ACMEAccount
	for i, account := range acmeConfig.Accounts {
		for _, d := range account.Domains {
			if d == domain {
				targetAccount = &acmeConfig.Accounts[i]
				break
			}
		}
		if targetAccount != nil {
			break
		}
	}

	if targetAccount == nil {
		return fmt.Errorf("在ACME配置中未找到域 %s 对应的账户", domain)
	}

	user, err := NewACMEUser(targetAccount.Email, filepath.Join(m.certDirectory, fmt.Sprintf("acme_%s.key", targetAccount.Name)))
	if err != nil {
		return fmt.Errorf("为账户 %s 创建ACME用户失败: %w", targetAccount.Name, err)
	}

	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("为账户 %s 创建ACME客户端失败: %w", targetAccount.Name, err)
	}

	var provider *cloudflare.DNSProvider
	if targetAccount.Provider == "cloudflare" {
		cfConfig := cloudflare.NewDefaultConfig()
		cfConfig.AuthEmail = targetAccount.Cloudflare.Email
		cfConfig.AuthKey = targetAccount.Cloudflare.APIKey
		cfConfig.AuthToken = targetAccount.Cloudflare.APIToken
		provider, err = cloudflare.NewDNSProviderConfig(cfConfig)
		if err != nil {
			return fmt.Errorf("为账户 %s 创建Cloudflare DNS提供商失败: %w", targetAccount.Name, err)
		}
	} else {
		return fmt.Errorf("不支持的ACME提供商: %s", targetAccount.Provider)
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return fmt.Errorf("为账户 %s 设置DNS-01提供商失败: %w", targetAccount.Name, err)
	}

	if user.GetRegistration() == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("ACME账户 %s 注册失败: %w", targetAccount.Name, err)
		}
		user.SetRegistration(reg)
		log.Printf("[CertManager] ACME账户 %s (%s) 注册成功", targetAccount.Name, targetAccount.Email)
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("获取证书失败 for %s: %w", domain, err)
	}

	domainDir := filepath.Join(m.certDirectory, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("创建域证书目录失败: %w", err)
	}

	err = os.WriteFile(filepath.Join(domainDir, "fullchain.pem"), certificates.Certificate, 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(domainDir, "privkey.pem"), certificates.PrivateKey, 0600)
	if err != nil {
		return err
	}

	log.Printf("[CertManager] 已成功获取并保存域 %s 的证书 (使用账户: %s)", domain, targetAccount.Name)

	m.mu.Lock()
	delete(m.certCache, domain)
	m.mu.Unlock()

	return nil
}

// ListCertificates 扫描证书目录并返回所有找到的证书的信息
func (m *CertManager) ListCertificates() ([]CertificateInfo, error) {
	m.mu.RLock()
	tlsConfig := m.tlsConfig
	m.mu.RUnlock()

	var certs []CertificateInfo
	processedDomains := make(map[string]bool)

	// 1. 处理手动证书
	for _, manualCert := range tlsConfig.Manual {
		for _, domain := range manualCert.Domains {
			if processedDomains[domain] {
				continue
			}
			processedDomains[domain] = true
			
			info := CertificateInfo{
				Domain: domain,
				Type: "手动指定",
				Status: "Unknown",
			}

			certPEM, err := os.ReadFile(manualCert.CertPath)
			if err != nil {
				info.Status = "File Not Found"
				certs = append(certs, info)
				continue
			}
			
			block, _ := pem.Decode(certPEM)
			if block == nil {
				info.Status = "Parse Failed"
				certs = append(certs, info)
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				info.Status = "Parse Failed"
				certs = append(certs, info)
				continue
			}

			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			info.Status = "Issued"
			info.Issuer = cert.Issuer.CommonName
			info.NotAfter = cert.NotAfter
			info.DaysLeft = daysLeft
			info.IsStaging = false
			info.FilePath = manualCert.CertPath
			certs = append(certs, info)
		}
	}

	// 2. 处理ACME证书
	if tlsConfig.ACME.Enabled {
		for _, account := range tlsConfig.ACME.Accounts {
			for _, domain := range account.Domains {
				if processedDomains[domain] {
					log.Printf("[CertManager] 警告: 域名 %s 同时被手动证书和ACME账户 '%s' 管理，将优先使用手动证书。", domain, account.Name)
					continue
				}
				processedDomains[domain] = true

				certPath := filepath.Join(m.certDirectory, domain, "fullchain.pem")
				
				info := CertificateInfo{
					Domain:   domain,
					Type:     "ACME",
					Status:   "Not Issued",
					Account:  account.Name,
				}

				certPEM, err := os.ReadFile(certPath)
				if err != nil {
					certs = append(certs, info)
					continue
				}

				block, _ := pem.Decode(certPEM)
				if block == nil {
					info.Status = "Parse Failed"
					certs = append(certs, info)
					continue
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					info.Status = "Parse Failed"
					certs = append(certs, info)
					continue
				}

				daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
				
				info.Status = "Issued"
				info.Issuer = cert.Issuer.CommonName
				info.NotAfter = cert.NotAfter
				info.DaysLeft = daysLeft
				info.IsStaging = strings.Contains(cert.Issuer.CommonName, "Staging")
				info.FilePath = certPath
				
				certs = append(certs, info)
			}
		}
	}

	return certs, nil
}