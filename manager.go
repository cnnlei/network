package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type BroadcastPayload struct {
	Connections      []*ConnectionInfo   `json:"connections"`
	RecentLogs       string              `json:"recentLogs"`
	RecentLogsByRule map[string][]string `json:"recentLogsByRule"`
}

type ConnectionInfo struct {
	ID         int64     `json:"id"`
	Protocol   string    `json:"protocol"`
	Rule       string    `json:"rule"`
	SubRule    string    `json:"sub_rule,omitempty"`
	ClientAddr string    `json:"clientAddr"`
	TargetAddr string    `json:"targetAddr"`
	StartTime  time.Time `json:"startTime"`
	conn       net.Conn  `json:"-"`
}
type ConnectionManager struct {
	connections map[int64]*ConnectionInfo
	clients     map[*websocket.Conn]bool
	nextConnID  int64
	mu          sync.RWMutex
}

func NewConnectionManager() *ConnectionManager {
	m := &ConnectionManager{
		connections: make(map[int64]*ConnectionInfo),
		clients:     make(map[*websocket.Conn]bool),
		nextConnID:  1,
	}
	go m.startCleanupTask()
	return m
}

func (m *ConnectionManager) startCleanupTask() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		m.cleanupStaleConnections()
	}
}

func (m *ConnectionManager) cleanupStaleConnections() {
	m.mu.Lock()
	var idsToClose []int64
	staleThreshold := 15 * time.Second
	var connectionsToClose []net.Conn

	for id, connInfo := range m.connections {
		if connInfo.Protocol == "WEB" && connInfo.TargetAddr == "匹配中..." && time.Since(connInfo.StartTime) > staleThreshold {
			idsToClose = append(idsToClose, id)
			if connInfo.conn != nil {
				connectionsToClose = append(connectionsToClose, connInfo.conn)
			}
		}
	}
	m.mu.Unlock()

	if len(idsToClose) > 0 {
		log.Printf("[Manager] 清理 %d 个陈旧的 '匹配中' 连接", len(idsToClose))
		for _, conn := range connectionsToClose {
			conn.Close()
		}
	}
}

func readRecentLogs(filePath string, n int) (string, map[string][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	var allLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	start := len(allLines) - n
	if start < 0 {
		start = 0
	}
	recentLines := allLines[start:]

	logsByRule := make(map[string][]string)
	
	re := regexp.MustCompile(`\[([^\]]+)\]`)

	for _, line := range allLines {
		if strings.Contains(line, "acme:") || strings.Contains(line, "[ACMEUser]") || strings.Contains(line, "[CertManager]") {
			continue 
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			fullRuleName := matches[1]
			if !strings.HasPrefix(fullRuleName, "Manager") && !strings.HasPrefix(fullRuleName, "IPFilter") && !strings.HasPrefix(fullRuleName, "LogJanitor") {
				logsByRule[fullRuleName] = append(logsByRule[fullRuleName], line)
			}
		}
	}

	return strings.Join(recentLines, "\n"), logsByRule, scanner.Err()
}

func (m *ConnectionManager) Add(protocol, rule string, clientConn, targetConn net.Conn) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	connID := atomic.AddInt64(&m.nextConnID, 1)

	clientAddr := "pending..."
	if clientConn != nil {
		clientAddr = clientConn.RemoteAddr().String()
	}
	targetAddr := "pending..."
	if targetConn != nil {
		targetAddr = targetConn.RemoteAddr().String()
	}

	m.connections[connID] = &ConnectionInfo{
		ID:         connID,
		Protocol:   protocol,
		Rule:       rule,
		ClientAddr: clientAddr,
		TargetAddr: targetAddr,
		StartTime:  time.Now(),
		conn:       clientConn,
	}
	return connID
}

func (m *ConnectionManager) AddHTTPConn(conn net.Conn, ruleName, subRuleName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	connID := atomic.AddInt64(&m.nextConnID, 1)

	m.connections[connID] = &ConnectionInfo{
		ID:         connID,
		Protocol:   "WEB",
		Rule:       ruleName,
		SubRule:    subRuleName,
		ClientAddr: conn.RemoteAddr().String(),
		TargetAddr: "匹配中...",
		StartTime:  time.Now(),
		conn:       conn,
	}
	go m.Broadcast()
}

func (m *ConnectionManager) UpdateSubRuleForConn(conn net.Conn, subRuleName string, frontendAddress string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var needsBroadcast bool
	for _, c := range m.connections {
		if c.conn == conn {
			if c.SubRule != subRuleName || c.TargetAddr != frontendAddress {
				c.SubRule = subRuleName
				c.TargetAddr = frontendAddress
				needsBroadcast = true
			}
			break
		}
	}
	if needsBroadcast {
		go m.Broadcast()
	}
}

func (m *ConnectionManager) Remove(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.connections[id]; ok {
		delete(m.connections, id)
		go m.Broadcast()
	}
}

func (m *ConnectionManager) RemoveByConn(conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var idToRemove int64 = -1
	for id, c := range m.connections {
		if c.conn == conn {
			idToRemove = id
			break
		}
	}
	if idToRemove != -1 {
		delete(m.connections, idToRemove)
		go m.Broadcast()
	}
}

func (m *ConnectionManager) UpdateTargetConn(id int64, targetConn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if conn, ok := m.connections[id]; ok {
		if targetConn != nil {
			conn.TargetAddr = targetConn.RemoteAddr().String()
		}
	}
}

func (m *ConnectionManager) Disconnect(id int64) bool {
	m.mu.Lock()
	conn, ok := m.connections[id]
	m.mu.Unlock()

	if ok && conn.conn != nil {
		log.Printf("[Manager] 正在断开连接 ID: %d", id)
		conn.conn.Close()
		return true
	}
	return false
}

func (m *ConnectionManager) GetAll() []*ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conns := make([]*ConnectionInfo, 0, len(m.connections))
	for _, conn := range m.connections {
		conns = append(conns, conn)
	}
	return conns
}

func (m *ConnectionManager) Broadcast() {
	conns := m.GetAll()
	recentLogs, logsByRule, err := readRecentLogs("forwarder.log", 50)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[Manager] 读取最新日志失败: %v", err)
		}
	}

	payload := BroadcastPayload{
		Connections:      conns,
		RecentLogs:       recentLogs,
		RecentLogsByRule: logsByRule,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Manager] Broadcast JSON 序列化失败: %v", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for client := range m.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("[Manager] WebSocket 写入错误: %v, 将移除客户端", err)
			client.Close()
			delete(m.clients, client)
		}
	}
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func (m *ConnectionManager) ServeWs(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket升级失败: %v", err)
		return
	}

	m.mu.Lock()
	m.clients[conn] = true
	m.mu.Unlock()
	log.Println("[Manager] 新的WebSocket客户端已连接")

	go m.Broadcast()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			m.mu.Lock()
			delete(m.clients, conn)
			m.mu.Unlock()
			log.Println("[Manager] 一个WebSocket客户端已断开")
			break
		}
	}
}