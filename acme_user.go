package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/go-acme/lego/v4/registration"
)

// ACMEUser 实现了 lego.User 接口
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// NewACMEUser 创建或加载一个 ACME 用户
func NewACMEUser(email string, keyPath string) (*ACMEUser, error) {
	var privateKey crypto.PrivateKey
	var err error

	if _, errStat := os.Stat(keyPath); os.IsNotExist(errStat) {
		log.Printf("[ACMEUser] 未找到ACME私钥，正在生成新私钥: %s", keyPath)
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成私钥失败: %w", err)
		}

		keyBytes, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("序列化私钥失败: %w", err)
		}
		pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, fmt.Errorf("保存私钥失败: %w", err)
		}

	} else {
		log.Printf("[ACMEUser] 正在从 %s 加载ACME私钥", keyPath)
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取私钥失败: %w", err)
		}
		pemBlock, _ := pem.Decode(keyBytes)
		if pemBlock == nil {
			return nil, fmt.Errorf("解析私钥PEM块失败")
		}
		privateKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
	}

	return &ACMEUser{
		Email: email,
		key:   privateKey,
	}, nil
}

// GetEmail 返回用户的邮箱
func (u *ACMEUser) GetEmail() string {
	return u.Email
}

// GetRegistration 返回用户的注册资源
func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey 返回用户的私钥
func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// SetRegistration 设置用户的注册资源
func (u *ACMEUser) SetRegistration(reg *registration.Resource) {
    u.Registration = reg
}