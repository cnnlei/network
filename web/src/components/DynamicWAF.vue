<template>
  <div class="dynamic-waf-container" @click="closeContextMenu">
    <div class="stats-cards">
      <div class="stat-card clickable" @click="showDetails('connections')">
        <h4>总连接数</h4>
        <p>{{ totalConnections }}</p>
      </div>
      <div class="stat-card clickable" @click="showDetails('ips')">
        <h4>活跃 IP 数</h4>
        <p>{{ activeIPs }}</p>
      </div>
      <div class="stat-card clickable" @click="showDetails('blocked')">
        <h4>拦截事件数</h4>
        <p>{{ totalBlocked }}</p>
      </div>
    </div>

    <div class="live-data-section">
      <div class="panel-section">
        <div class="tabs">
          <button :class="{ active: rankingTab === 'access' }" @click="rankingTab = 'access'">访问排名 (累计)</button>
          <button :class="{ active: rankingTab === 'count' }" @click="rankingTab = 'count'">连接数排名 (实时)</button>
        </div>
        <div class="tab-content">
          <table v-if="rankingTab === 'access'" class="data-table">
            <thead>
              <tr>
                <th>排名</th>
                <th>IP 地址</th>
                <th>总访问次数</th>
                <th>归属地</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(ip, index) in cumulativeRankedIPs" :key="ip.address">
                <td>{{ index + 1 }}</td>
                <td><IPAddress :ip="ip.address" @show-menu="openIpContextMenu" /></td>
                <td>{{ ip.count }}</td>
                <td>{{ ip.location }}</td>
              </tr>
              <tr v-if="cumulativeRankedIPs.length === 0">
                <td colspan="4" class="empty-state">暂无数据...</td>
              </tr>
            </tbody>
          </table>
          <table v-if="rankingTab === 'count'" class="data-table">
            <thead>
              <tr>
                <th>排名</th>
                <th>IP 地址</th>
                <th>实时连接数 (10s内)</th>
                <th>归属地</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(ip, index) in realtimeRankedIPs" :key="ip.address">
                <td>{{ index + 1 }}</td>
                <td><IPAddress :ip="ip.address" @show-menu="openIpContextMenu" /></td>
                <td>{{ ip.count }}</td>
                <td>{{ ip.location }}</td>
              </tr>
              <tr v-if="realtimeRankedIPs.length === 0">
                <td colspan="4" class="empty-state">暂无数据...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel-section">
        <div class="tabs">
          <button :class="{ active: logTab === 'realtime' }" @click="logTab = 'realtime'">实时 (包含拦截)</button>
          <button :class="{ active: logTab === 'blocked' }" @click="logTab = 'blocked'">拦截</button>
        </div>
        <div class="tab-content">
           <div v-if="logTab === 'realtime'" class="logs-container dark-theme">
              <div v-if="allPackets.length === 0" class="empty-state-small">等待连接...</div>
              <div
                v-else
                v-for="packet in allPackets"
                :key="packet.id"
                class="log-line clickable"
                @click="showPacketDetails(packet)"
              >
                  <span class="log-time">{{ new Date(packet.timestamp).toLocaleTimeString() }}</span>
                   <span :class="['log-level', packet.isBlocked ? 'log-block' : 'log-info']">{{ packet.isBlocked ? 'BLOCK' : 'PASS' }}</span>
                  <span class="log-message">
                      来自 <strong><IPAddress :ip="packet.request.ip" @show-menu="openIpContextMenu" /></strong> 的 {{packet.request.method}} 请求.
                  </span>
              </div>
          </div>
          <div v-if="logTab === 'blocked'" class="logs-container dark-theme">
            <div v-if="blockedPackets.length === 0" class="empty-state-small">等待拦截事件...</div>
            <div
              v-else
              v-for="packet in blockedPackets"
              :key="packet.id"
              class="log-line clickable"
              @click="showPacketDetails(packet)"
            >
              <span class="log-time">{{ new Date(packet.timestamp).toLocaleString() }}</span>
              <span class="log-level log-block">BLOCK</span>
              <span class="log-message">
                来自 <strong><IPAddress :ip="packet.request.ip" @show-menu="openIpContextMenu" /></strong> 的请求被拦截.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="isModalOpen" class="modal-overlay" @click.self="closeModal">
      <div class="modal-content large">
        <h2>{{ modalTitle }}</h2>
        
        <div v-if="modalMode === 'packet'" class="packet-details">
          <div class="detail-section">
            <h4>请求信息 (Request)</h4>
            <div class="detail-grid">
              <div><strong>时间:</strong> {{ new Date(selectedPacket.timestamp).toLocaleString() }}</div>
              <div><strong>源 IP:</strong> <IPAddress :ip="selectedPacket.request.ip" @show-menu="openIpContextMenu" /></div>
              <div><strong>方法:</strong> {{ selectedPacket.request.method }}</div>
              <div><strong>协议:</strong> {{ selectedPacket.request.protocol }}</div>
              <div class="grid-span-2"><strong>目标 URI:</strong> {{ selectedPacket.request.uri }}</div>
            </div>
          </div>
          <div class="detail-section">
            <h4>请求头 (Request Headers)</h4>
            <pre class="headers-view">{{ formatHeaders(selectedPacket.request.headers) }}</pre>
          </div>
          <div class="detail-section">
            <h4>请求体 (Request Body)</h4>
            <pre class="payload-view">{{ selectedPacket.request.payload || '(无内容)' }}</pre>
          </div>
           <div class="detail-section">
            <h4>响应信息 (Response)</h4>
            <div class="detail-grid">
                <div><strong>状态码:</strong> <span :class="statusClass(selectedPacket.response.status)">{{ selectedPacket.response.status }}</span></div>
                <div class="grid-span-2"><strong>原因:</strong> {{ selectedPacket.response.reason }}</div>
            </div>
          </div>
          <div class="detail-section">
            <h4>响应头 (Response Headers)</h4>
            <pre class="headers-view">{{ formatHeaders(selectedPacket.response.headers) }}</pre>
          </div>
          <div class="detail-section">
            <h4>响应体 (Response Body)</h4>
            <pre class="payload-view">{{ selectedPacket.response.body || '(无内容)' }}</pre>
          </div>
        </div>

        <div v-else class="list-view">
            <table class="details-table">
                <thead v-if="modalMode === 'connections'">
                    <tr><th>时间</th><th>IP 地址</th><th>请求路径</th><th>状态</th></tr>
                </thead>
                <thead v-if="modalMode === 'ips'">
                    <tr><th>IP 地址</th><th>连接数</th><th>归属地</th></tr>
                </thead>
                <thead v-if="modalMode === 'blocked'">
                    <tr><th>时间</th><th>IP 地址</th><th>拦截原因</th><th>请求路径</th></tr>
                </thead>
                <tbody>
                    <template v-if="modalMode === 'connections'">
                        <tr v-for="packet in allPackets" :key="packet.id" @click="showPacketDetails(packet)" class="clickable-row">
                            <td>{{ new Date(packet.timestamp).toLocaleTimeString() }}</td>
                            <td><IPAddress :ip="packet.request.ip" @show-menu="openIpContextMenu" /></td>
                            <td>{{ packet.request.uri }}</td>
                            <td><span :class="['log-level', packet.isBlocked ? 'log-block' : 'log-info']">{{ packet.isBlocked ? 'BLOCK' : 'PASS' }}</span></td>
                        </tr>
                    </template>
                    <template v-if="modalMode === 'ips'">
                        <tr v-for="ip in cumulativeRankedIPs" :key="ip.address">
                            <td><IPAddress :ip="ip.address" @show-menu="openIpContextMenu" /></td>
                            <td>{{ ip.count }}</td>
                            <td>{{ ip.location }}</td>
                        </tr>
                    </template>
                    <template v-if="modalMode === 'blocked'">
                        <tr v-for="packet in blockedPackets" :key="packet.id" @click="showPacketDetails(packet)" class="clickable-row">
                            <td>{{ new Date(packet.timestamp).toLocaleString() }}</td>
                            <td><IPAddress :ip="packet.request.ip" @show-menu="openIpContextMenu" /></td>
                            <td>{{ packet.response.reason }}</td>
                            <td>{{ packet.request.uri }}</td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <div class="form-actions">
          <button @click="closeModal" class="btn-cancel">关闭</button>
        </div>
      </div>
    </div>

    <div v-if="isContextMenuOpen" class="context-menu" :style="{ top: `${contextMenuPosition.y}px`, left: `${contextMenuPosition.x}px` }">
        <div class="context-menu-header">添加到 IP 集</div>
        <ul>
            <li v-for="list in ipLists" :key="list.Name" @click="addIpToList(list.Name)">{{ list.Name }} ({{ list.Type }})</li>
            <li v-if="ipLists.length === 0" class="no-lists">没有可用的 IP 集。</li>
        </ul>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue';
import IPAddress from './IPAddress.vue';

const totalConnections = ref(0);
const activeIPs = ref(0);
const totalBlocked = ref(0);
const cumulativeRankedIPs = ref([]);
const allPackets = ref([]);
const ipLists = ref([]);

const logTab = ref('realtime');
const rankingTab = ref('access');

const isModalOpen = ref(false);
const selectedPacket = ref(null);
const modalMode = ref('');

const isContextMenuOpen = ref(false);
const contextMenuPosition = ref({ x: 0, y: 0 });
const selectedIpForMenu = ref(null);

let intervalId = null;

const modalTitle = computed(() => {
    switch (modalMode.value) {
        case 'packet': return '数据包详情';
        case 'connections': return '所有连接记录';
        case 'ips': return '活跃 IP 列表';
        case 'blocked': return '所有拦截事件';
        default: return '详情';
    }
});

const blockedPackets = computed(() => allPackets.value.filter(p => p.isBlocked));

const realtimeRankedIPs = computed(() => {
    const now = Date.now();
    const tenSecondsAgo = now - 10000;
    const recentPackets = allPackets.value.filter(p => p.timestamp >= tenSecondsAgo);
    const counts = recentPackets.reduce((acc, p) => {
        acc[p.request.ip] = (acc[p.request.ip] || 0) + 1;
        return acc;
    }, {});
    return Object.entries(counts)
        .map(([address, count]) => ({
            address,
            count,
            location: cumulativeRankedIPs.value.find(ip => ip.address === address)?.location || '查询中...'
        }))
        .sort((a, b) => b.count - a.count);
});

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const fetchIpLists = async () => {
    try {
        const response = await fetch(getApiUrl('/api/ip-lists'));
        if (response.ok) {
            ipLists.value = await response.json() || [];
        }
    } catch (error) {
        console.error('获取 IP 集列表失败:', error);
    }
};

const addIpToList = async (listName) => {
    if (!selectedIpForMenu.value) return;
    try {
        const response = await fetch(getApiUrl(`/api/ip-lists/${listName}/ips`), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: selectedIpForMenu.value })
        });
        if (response.ok) {
            alert(`IP ${selectedIpForMenu.value} 已成功添加到 ${listName}`);
        } else {
            const error = await response.json();
            alert(`添加失败: ${error.error}`);
        }
    } catch (error) {
        alert(`请求失败: ${error.message}`);
    }
    closeContextMenu();
};

const openIpContextMenu = (event) => {
    selectedIpForMenu.value = event.ip;
    contextMenuPosition.value = { x: event.x, y: event.y };
    isContextMenuOpen.value = true;
};

const closeContextMenu = () => {
    isContextMenuOpen.value = false;
    selectedIpForMenu.value = null;
};

const generateMockData = () => {
    const mockIPs = ['1.1.1.1', '8.8.8.8', '208.67.222.222', '114.114.114.114', '180.76.76.76', '223.5.5.5', '101.226.4.6', '120.53.229.138', '2.58.60.13', '91.245.227.1'];
    const mockURIs = ['/admin/login.php', '/api/v1/users', '/index.html', '/config/db.json', '/.env'];
    const mockReasons = ['SQL Injection Attempt', 'Path Traversal', 'XSS Attack', 'Rate Limit Exceeded'];
    const mockMethods = ['GET', 'POST', 'PUT'];
    const mockUserAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'python-requests/2.28.1',
        'curl/7.86.0',
    ];
    
    const isBlocked = Math.random() < 0.25;
    const method = mockMethods[Math.floor(Math.random() * mockMethods.length)];
    const randomIP = mockIPs[Math.floor(Math.random() * mockIPs.length)];
    
    const packet = {
        id: Date.now() + Math.random(),
        timestamp: Date.now(),
        isBlocked: isBlocked,
        request: {
            ip: randomIP,
            uri: mockURIs[Math.floor(Math.random() * mockURIs.length)],
            method: method,
            protocol: 'HTTP/1.1',
            headers: { 
                'Host': 'example.com', 
                'User-Agent': mockUserAgents[Math.floor(Math.random() * mockUserAgents.length)], 
                'Accept': '*/*',
                'Content-Type': method === 'POST' ? 'application/x-www-form-urlencoded' : undefined,
            },
            payload: method === 'POST' ? `username=admin&password=' or 1=1;--` : null,
        },
        response: {},
    };

    if (isBlocked) {
        packet.response = {
            status: 403,
            reason: mockReasons[Math.floor(Math.random() * mockReasons.length)],
            headers: { 'Content-Type': 'text/html', 'Server': 'Go-Forwarder-WAF' },
            body: '<h1>403 Forbidden</h1>\n<p>Your request was blocked by the security policy.</p>'
        };
        totalBlocked.value++;
    } else {
        packet.response = {
            status: 200,
            reason: 'OK',
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Server': 'Go-Forwarder' },
            body: JSON.stringify({ success: true, message: "Request processed successfully.", data: { id: 123, user: "demo" } }, null, 2),
        };
    }
    
    allPackets.value.unshift(packet);
    if(allPackets.value.length > 500) allPackets.value.pop(); // Keep the list from growing indefinitely

    totalConnections.value++;

    const existingEntry = cumulativeRankedIPs.value.find(ip => ip.address === randomIP);
    if (existingEntry) {
        existingEntry.count++;
    } else {
        cumulativeRankedIPs.value.push({ address: randomIP, count: 1, location: '查询中...' });
        fetchIPLocation(randomIP);
    }

    cumulativeRankedIPs.value.sort((a, b) => b.count - a.count);
    activeIPs.value = cumulativeRankedIPs.value.length;
};

const showDetails = (mode) => {
    modalMode.value = mode;
    isModalOpen.value = true;
};

const showPacketDetails = (packet) => {
  modalMode.value = 'packet';
  selectedPacket.value = packet;
  isModalOpen.value = true;
};

const closeModal = () => {
  isModalOpen.value = false;
  selectedPacket.value = null;
};

const formatHeaders = (headers = {}) => {
  return Object.entries(headers)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n');
};

const statusClass = (status) => {
    if (status >= 500) return 'status-5xx';
    if (status >= 400) return 'status-4xx';
    if (status >= 300) return 'status-3xx';
    return 'status-2xx';
};

const fetchIPLocation = async (ip) => {
    if (ipLocationCache.has(ip)) {
        const entry = cumulativeRankedIPs.value.find(item => item.address === ip);
        if (entry) entry.location = ipLocationCache.get(ip);
        return;
    }
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.ok) {
            const data = await response.json();
            const location = data.country && data.city ? `${data.country} ${data.city}` : '未知';
            const entry = cumulativeRankedIPs.value.find(item => item.address === ip);
            if (entry) entry.location = location;
            ipLocationCache.set(ip, location);
        }
    } catch (error) {
        console.error(`获取IP归属地失败 for ${ip}:`, error);
    }
};

onMounted(() => {
  fetchIpLists();
  intervalId = setInterval(generateMockData, 1200);
});

onUnmounted(() => {
  if (intervalId) {
    clearInterval(intervalId);
  }
});
</script>

<style scoped>
.dynamic-waf-container { padding: 1rem; }
.stats-cards { display: flex; gap: 1.5rem; margin-bottom: 2rem; }
.stat-card { background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 1.5rem; flex-grow: 1; text-align: center; transition: transform 0.2s, box-shadow 0.2s; }
.stat-card.clickable { cursor: pointer; }
.stat-card.clickable:hover { transform: translateY(-5px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
.stat-card h4 { margin: 0 0 0.5rem 0; color: #495057; }
.stat-card p { margin: 0; font-size: 2rem; font-weight: bold; color: #007bff; }
.live-data-section { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
.panel-section { display: flex; flex-direction: column; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); overflow: hidden; }
.tabs { display: flex; border-bottom: 1px solid #e0e0e0; padding: 0 1rem; flex-shrink: 0; }
.tabs button { padding: 0.8rem 1.2rem; border: none; background-color: transparent; cursor: pointer; font-size: 0.9rem; position: relative; color: #6c757d; }
.tabs button.active { color: #007bff; font-weight: 600; }
.tabs button.active::after { content: ''; position: absolute; bottom: -1px; left: 0; width: 100%; height: 2px; background-color: #007bff; }
.tab-content { flex-grow: 1; min-height: 0; height: 65vh; overflow-y: auto; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th, .data-table td { padding: 0.8rem; text-align: left; border-bottom: 1px solid #e0e0e0; }
.data-table tr:last-child td { border-bottom: none; }
.data-table th { background-color: #f8f9fa; position: sticky; top: 0; z-index: 1; }
.empty-state { text-align: center; color: #6c757d; padding: 2rem; }
.logs-container { height: 100%; }
.dark-theme { background-color: #282c34; color: #dcdfe4; }
.empty-state-small { padding: 2rem; text-align: center; color: #6c757d; }
.log-line { display: flex; flex-wrap: nowrap; gap: 1rem; align-items: baseline; padding: 0.2rem 0; }
.log-line.clickable { cursor: pointer; transition: background-color 0.2s; }
.log-line.clickable:hover { background-color: #3a3f4b; }
.log-time { color: #999; flex-shrink: 0; }
.log-level { font-weight: bold; flex-shrink: 0; text-align: center; width: 50px; }
.log-block { color: #ff6347; }
.log-info { color: #87cefa; }
.log-message { flex-grow: 1; word-break: break-all; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.log-message strong { color: #f0e68c; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); display: flex; justify-content: center; align-items: center; z-index: 1000; }
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 90%; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
.modal-content.large { max-width: 800px; }
.modal-content h2 { margin-top: 0; border-bottom: 1px solid #e0e0e0; padding-bottom: 1rem; margin-bottom: 1.5rem; }
.form-actions { display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem; }
.btn-cancel { padding: 0.7rem 1.5rem; border-radius: 5px; border: none; background-color: #6c757d; color: white; cursor: pointer; }
.packet-details { display: flex; flex-direction: column; gap: 1.5rem; max-height: 75vh; overflow-y: auto; padding-right: 1rem; }
.detail-section h4 { margin: 0 0 0.8rem 0; color: #333; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
.detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.8rem; font-size: 0.9rem; }
.detail-grid .grid-span-2 { grid-column: span 2; }
.detail-grid div { background-color: #f8f9fa; padding: 0.5rem; border-radius: 4px; word-break: break-all; }
.detail-grid strong { color: #495057; }
.headers-view, .payload-view { background-color: #282c34; color: #dcdfe4; font-family: "SFMono-Regular", Consolas, Menlo, monospace; padding: 1rem; border-radius: 5px; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; font-size: 0.85rem; }
.list-view { max-height: 60vh; overflow-y: auto; }
.details-table { width: 100%; border-collapse: collapse; }
.details-table th, .details-table td { padding: 0.8rem; text-align: left; border-bottom: 1px solid #e0e0e0; }
.details-table th { background-color: #f8f9fa; position: sticky; top: 0; }
.details-table .clickable-row { cursor: pointer; }
.details-table .clickable-row:hover { background-color: #f1f3f5; }
.status-2xx { color: #28a745; font-weight: bold; }
.status-3xx { color: #fd7e14; font-weight: bold; }
.status-4xx, .status-5xx { color: #dc3545; font-weight: bold; }
.context-menu { position: fixed; background-color: white; border: 1px solid #ccc; box-shadow: 0 4px 12px rgba(0,0,0,0.15); border-radius: 6px; z-index: 2000; min-width: 180px; padding: 5px 0; }
.context-menu-header { font-weight: bold; padding: 8px 12px; font-size: 0.9rem; color: #333; border-bottom: 1px solid #eee; }
.context-menu ul { list-style: none; padding: 0; margin: 0; }
.context-menu li { padding: 8px 12px; cursor: pointer; font-size: 0.9rem; }
.context-menu li:hover { background-color: #007bff; color: white; }
.context-menu .no-lists { color: #888; cursor: default; }
.context-menu .no-lists:hover { background-color: transparent; color: #888; }
</style>