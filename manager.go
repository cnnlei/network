package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type BroadcastPayload struct {
	Connections []*ConnectionInfo `json:"connections"`
	RecentLogs  string            `json:"recentLogs"`
}
type ConnectionInfo struct {
	ID         int64     `json:"ID"`
	Protocol   string    `json:"Protocol"`
	Rule       string    `json:"Rule"`
	ClientAddr string    `json:"ClientAddr"`
	TargetAddr string    `json:"TargetAddr"`
	StartTime  time.Time `json:"startTime"`
	clientConn net.Conn `json:"-"`
	targetConn net.Conn `json:"-"`
}
type ConnectionManager struct {
	connections map[int64]*ConnectionInfo
	clients     map[*websocket.Conn]bool
	nextConnID  int64
	mu          sync.RWMutex
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[int64]*ConnectionInfo),
		clients:     make(map[*websocket.Conn]bool),
		nextConnID:  1,
	}
}

func readLastNLines(filePath string, n int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil { return "", err }
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() { lines = append(lines, scanner.Text()) }
	start := len(lines) - n
	if start < 0 { start = 0 }
	return strings.Join(lines[start:], "\n"), scanner.Err()
}

func (m *ConnectionManager) Add(protocol, rule string, clientConn, targetConn net.Conn) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	connID := m.nextConnID
	m.nextConnID++
	clientAddr := "pending..."
	if clientConn != nil { clientAddr = clientConn.RemoteAddr().String() }
	targetAddr := "pending..."
	if targetConn != nil { targetAddr = targetConn.RemoteAddr().String() }
	m.connections[connID] = &ConnectionInfo{
		ID:         connID,
		Protocol:   protocol,
		Rule:       rule,
		ClientAddr: clientAddr,
		TargetAddr: targetAddr,
		StartTime:  time.Now(),
		clientConn: clientConn,
		targetConn: targetConn,
	}
	return connID
}

func (m *ConnectionManager) Remove(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.connections, id)
}

func (m *ConnectionManager) UpdateTargetConn(id int64, targetConn net.Conn) {
    m.mu.Lock()
    defer m.mu.Unlock()
    if conn, ok := m.connections[id]; ok {
        conn.targetConn = targetConn
		if targetConn != nil {
			conn.TargetAddr = targetConn.RemoteAddr().String()
		}
    }
}

func (m *ConnectionManager) Disconnect(id int64) bool {
	m.mu.Lock()
	conn, ok := m.connections[id]
	m.mu.Unlock()
	if ok {
		log.Printf("[Manager] 正在断开连接 ID: %d", id)
		if conn.clientConn != nil { conn.clientConn.Close() }
		if conn.targetConn != nil { conn.targetConn.Close() }
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
	logs, err := readLastNLines("forwarder.log", 50)
	if err != nil { log.Printf("[Manager] 读取最新日志失败: %v", err) }

	payload := BroadcastPayload{ Connections: conns, RecentLogs: logs }
	data, err := json.Marshal(payload)
	if err != nil { log.Printf("[Manager] Broadcast JSON 序列化失败: %v", err); return }

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

var upgrader = websocket.Upgrader{ CheckOrigin: func(r *http.Request) bool { return true } }

func (m *ConnectionManager) ServeWs(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil { log.Printf("WebSocket升级失败: %v", err); return }
	
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