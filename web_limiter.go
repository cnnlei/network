package main

import (
	"sync"
)

// IPConnectionLimiter 跟踪每个规则下每个IP的连接数
type IPConnectionLimiter struct {
	mu      sync.Mutex
	counts  map[string]map[string]int
}

func NewIPConnectionLimiter() *IPConnectionLimiter {
	return &IPConnectionLimiter{
		counts: make(map[string]map[string]int),
	}
}

// Check 检查给定IP是否已达到连接限制。
// 注意：此检查应在连接数已增加后进行。
func (l *IPConnectionLimiter) Check(ruleName, ip string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if count, ok := l.counts[ruleName][ip]; ok {
		// 因为计数包含了当前连接，所以只有当计数严格大于限制时才拒绝。
		if count > limit {
			return false // Limit exceeded
		}
	}
	return true // Allowed
}

// Increment 增加给定IP的连接计数
func (l *IPConnectionLimiter) Increment(ruleName, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.counts[ruleName]; !ok {
		l.counts[ruleName] = make(map[string]int)
	}
	l.counts[ruleName][ip]++
}

// Decrement 减少给定IP的连接计数
func (l *IPConnectionLimiter) Decrement(ruleName, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.counts[ruleName]; ok {
		if _, ok := l.counts[ruleName][ip]; ok {
			l.counts[ruleName][ip]--
			if l.counts[ruleName][ip] <= 0 {
				delete(l.counts[ruleName], ip)
			}
			if len(l.counts[ruleName]) == 0 {
				delete(l.counts, ruleName)
			}
		}
	}
}