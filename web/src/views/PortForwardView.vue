<script setup>
import { ref, onMounted, onUnmounted, computed, nextTick, watch } from 'vue';
import IconEdit from '../components/icons/IconEdit.vue';
import IconDelete from '../components/icons/IconDelete.vue';
import IconLink from '../components/icons/IconLink.vue';
import IconLogs from '../components/icons/IconLogs.vue';

const rules = ref([]);
const ruleStatuses = ref({}); // **NEW**: To store live statuses
const ipLists = ref({
  whitelists: {},
  blacklists: {},
  ip_sets: {},
  country_ip_lists: {},
  url_ip_sets: {},
});
const connections = ref([]);
const recentLogsByRule = ref({});

// --- Modal States ---
const isRuleModalOpen = ref(false);
const isConnModalOpen = ref(false);
const isLogModalOpen = ref(false);
const isAddIpModalOpen = ref(false);

// --- Tooltip States & Logic ---
const tooltipRef = ref(null);
const isTooltipVisible = ref(false);
const tooltipContent = ref([]);
const tooltipTop = ref(0);
const tooltipLeft = ref(0);
const tooltipCurrentPage = ref(1);
const tooltipPageSize = ref(20);
const tooltipTotalPages = ref(1);
const tooltipJumpToPage = ref(1);
const tooltipRuleName = ref('');
let hideTooltipTimeout = null;

// --- Modal Content States ---
const modalMode = ref('add');
const uiState = ref({
  protocolType: 'tcp',
  ipVersion: 'any',
});
const currentRule = ref({});
const originalRuleName = ref('');
const connectionsForModal = ref([]);
const ruleForModal = ref('');

// --- Log Modal Pagination ---
const logsForModal = ref([]);
const ruleForLogModal = ref('');
const isLoadingLogs = ref(false);
const logModalCurrentPage = ref(1);
const logModalPageSize = ref(50);
const logModalTotalPages = ref(1);
const logModalJumpToPage = ref(1);

// --- Add IP to List Modal State ---
const ipToAdd = ref('');
const selectedCategory = ref('whitelists');
const selectedIpList = ref('');

let socket = null;

const availableWhitelists = computed(() => {
  const lists = [];
  for (const name in ipLists.value.whitelists) lists.push({ name, source: 'IP白名单' });
  for (const name in ipLists.value.ip_sets) lists.push({ name, source: 'IP集' });
  for (const name in ipLists.value.country_ip_lists) lists.push({ name, source: '国家IP' });
  for (const name in ipLists.value.url_ip_sets) lists.push({ name, source: 'URL IP集' });
  return lists;
});
const availableBlacklists = computed(() => {
  const lists = [];
  for (const name in ipLists.value.blacklists) lists.push({ name, source: 'IP黑名单' });
  for (const name in ipLists.value.ip_sets) lists.push({ name, source: 'IP集' });
  for (const name in ipLists.value.country_ip_lists) lists.push({ name, source: '国家IP' });
  for (const name in ipLists.value.url_ip_sets) lists.push({ name, source: 'URL IP集' });
  return lists;
});

const availableListsForCategory = computed(() => {
    if (!selectedCategory.value || !ipLists.value[selectedCategory.value]) {
        return {};
    }
    return ipLists.value[selectedCategory.value];
});

const connectionsCount = computed(() => {
    const counts = {};
    if (rules.value) {
        for (const rule of rules.value) {
            counts[rule.Name] = connections.value.filter(c => c.rule === rule.Name).length;
        }
    }
    return counts;
});


const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const connectWebSocket = () => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${wsProtocol}//${window.location.hostname}:8080/ws`);
  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.connections !== undefined) {
        connections.value = payload.connections;
      }
      if (payload.recentLogsByRule !== undefined) {
        recentLogsByRule.value = payload.recentLogsByRule;
      }
      if (isConnModalOpen.value) {
        connectionsForModal.value = payload.connections.filter(c => c.rule === ruleForModal.value);
      }
    } catch (e) { console.error("解析WebSocket数据失败:", e); }
  };
  socket.onclose = () => setTimeout(connectWebSocket, 3000);
};

const fetchRuleStatuses = async () => {
    try {
        const response = await fetch(getApiUrl('/api/rules/status'));
        if(response.ok) {
            ruleStatuses.value = await response.json();
        }
    } catch (error) {
        console.error('获取规则状态失败:', error);
    }
};

const fetchRules = async () => {
  try {
    const response = await fetch(getApiUrl('/api/rules'));
    if (response.ok) {
        rules.value = await response.json() || [];
        await fetchRuleStatuses();
    }
  } catch (error) { console.error('加载规则列表失败:', error); }
};

const fetchIPLists = async () => {
  try {
    const response = await fetch(getApiUrl('/api/ip-lists'));
    if (response.ok) {
      const data = await response.json();
      ipLists.value = {
        whitelists: data.whitelists || {},
        blacklists: data.blacklists || {},
        ip_sets: data.ip_sets || {},
        country_ip_lists: data.country_ip_lists || {},
        url_ip_sets: data.url_ip_sets || {},
      };
    }
  } catch (error) { console.error('加载IP名单失败:', error); }
};

const fetchPaginatedLogs = async (ruleName, page, pageSize) => {
    const response = await fetch(getApiUrl(`/api/logs?rule=${ruleName}&page=${page}&pageSize=${pageSize}`));
    if (!response.ok) throw new Error('Failed to fetch logs');
    return await response.json();
}

const showLogTooltip = async (event, rule) => {
    clearTimeout(hideTooltipTimeout);
    isTooltipVisible.value = true;
    tooltipRuleName.value = rule.Name;
    tooltipCurrentPage.value = 1;
    await loadTooltipLogs();

    await nextTick();
    
    if (!tooltipRef.value) return;

    const rect = event.target.getBoundingClientRect();
    const tooltipHeight = tooltipRef.value.offsetHeight;
    const tooltipWidth = tooltipRef.value.offsetWidth;
    const spaceBelow = window.innerHeight - rect.bottom;
    const spaceRight = window.innerWidth - rect.left;

    tooltipTop.value = (spaceBelow < tooltipHeight + 10) ? rect.top - tooltipHeight - 10 : rect.bottom + 10;
    tooltipLeft.value = (spaceRight < tooltipWidth) ? rect.right - tooltipWidth : rect.left;
};

const loadTooltipLogs = async () => {
    tooltipContent.value = ["加载中..."];
    try {
        const data = await fetchPaginatedLogs(tooltipRuleName.value, tooltipCurrentPage.value, tooltipPageSize.value);
        tooltipContent.value = data.logs.length > 0 ? data.logs : ['暂无日志记录'];
        tooltipTotalPages.value = data.totalPages;
        tooltipJumpToPage.value = tooltipCurrentPage.value;
    } catch (e) {
        tooltipContent.value = ['日志加载失败'];
    }
}

const handleTooltipJump = () => {
    const page = parseInt(tooltipJumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= tooltipTotalPages.value) {
        tooltipCurrentPage.value = page;
        loadTooltipLogs();
    } else {
        tooltipJumpToPage.value = tooltipCurrentPage.value;
    }
}

const hideLogTooltip = () => {
    hideTooltipTimeout = setTimeout(() => {
        isTooltipVisible.value = false;
    }, 200);
};

const cancelTooltipHide = () => {
    clearTimeout(hideTooltipTimeout);
}

const openLogModal = async (rule) => {
  ruleForLogModal.value = rule.Name;
  isLogModalOpen.value = true;
  logModalCurrentPage.value = 1;
  await loadModalLogs();
};

const loadModalLogs = async () => {
    isLoadingLogs.value = true;
    logsForModal.value = ['正在加载日志...'];
    try {
        const data = await fetchPaginatedLogs(ruleForLogModal.value, logModalCurrentPage.value, logModalPageSize.value);
        logsForModal.value = data.logs.length > 0 ? data.logs : ['该规则下暂无日志记录。'];
        logModalTotalPages.value = data.totalPages;
        logModalJumpToPage.value = logModalCurrentPage.value;
    } catch (error) {
        logsForModal.value = ['加载失败，无法连接到API。'];
    } finally {
        isLoadingLogs.value = false;
    }
};

const handleModalJump = () => {
    const page = parseInt(logModalJumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= logModalTotalPages.value) {
        logModalCurrentPage.value = page;
        loadModalLogs();
    } else {
        alert(`请输入一个介于 1 和 ${logModalTotalPages.value} 之间的有效页码。`);
        logModalJumpToPage.value = logModalCurrentPage.value;
    }
}

const toggleRule = async (rule) => {
  try {
    const response = await fetch(getApiUrl(`/api/rules/${rule.Name}/toggle`), { method: 'POST' });
    const result = await response.json();
    if (response.ok) {
      rule.Enabled = result.enabled;
      fetchRuleStatuses(); // Refresh statuses
    } else {
      alert(`切换失败: ${result.error}`);
    }
  } catch (error) {
    alert('请求失败');
  }
};

const deleteRule = async (ruleName) => {
  if (!confirm(`确定要删除规则 "${ruleName}" 吗？`)) return;
  try {
    const response = await fetch(getApiUrl(`/api/rules/${ruleName}`), { method: 'DELETE' });
    const result = await response.json();
    if (response.ok) {
      fetchRules(); // This will also trigger a status fetch
    } else { alert(`删除失败: ${result.error}`); }
  } catch (error) { alert('删除请求失败'); }
};

const handleSubmit = async () => {
  if (!currentRule.value.Name || !currentRule.value.ListenPort || !currentRule.value.ForwardAddr || !currentRule.value.ForwardPort) {
    alert('所有字段均为必填项！');
    return;
  }
  if (currentRule.value.AccessControl.Mode !== 'disabled' && !currentRule.value.AccessControl.ListName) {
    alert('启用白名单或黑名单时，必须选择一个IP名单！');
    return;
  }
  
  const buildProtocolString = () => {
    const { protocolType, ipVersion } = uiState.value;
    if (protocolType === 'tcp,udp') {
      return 'tcp,udp';
    }
    if (ipVersion === 'ipv4') {
      return `${protocolType}4`;
    }
    if (ipVersion === 'ipv6') {
      return `${protocolType}6`;
    }
    return protocolType;
  };
  
  const listenAddrMap = {
    'any': '',
    'ipv4': '0.0.0.0',
    'ipv6': '::'
  };
  
  const finalRule = {
    ...currentRule.value,
    ListenPort: parseInt(currentRule.value.ListenPort, 10) || 0,
    ForwardPort: parseInt(currentRule.value.ForwardPort, 10) || 0,
    Protocol: buildProtocolString(),
    ListenAddr: listenAddrMap[uiState.value.ipVersion],
    RateLimit: parseInt(currentRule.value.RateLimit, 10) || 0,
    ConnectionLimit: parseInt(currentRule.value.ConnectionLimit, 10) || 0,
    UDPSessionTimeout: parseInt(currentRule.value.UDPSessionTimeout, 10) || 0,
    UDPMaxSessions: parseInt(currentRule.value.UDPMaxSessions, 10) || 0,
    UDPMaxBlockLength: parseInt(currentRule.value.UDPMaxBlockLength, 10) || 0,
  };

  const url = modalMode.value === 'add' ? getApiUrl('/api/rules') : getApiUrl(`/api/rules/${originalRuleName.value}`);
  const method = modalMode.value === 'add' ? 'POST' : 'PUT';

  try {
    const response = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(finalRule) });
    const result = await response.json();
    if (response.ok) {
      isRuleModalOpen.value = false;
      fetchRules(); // This will also trigger a status fetch
    } else { alert(`操作失败: ${result.error}`); }
  } catch (error) { alert('请求失败'); }
};

const disconnectConnection = async (connId) => {
  if (!confirm(`确定要断开连接 ID: ${connId} 吗？`)) return;
  try {
    const response = await fetch(getApiUrl(`/api/connections/${connId}/disconnect`), { method: 'POST' });
    if (!response.ok) { alert('断开连接失败'); }
  } catch (error) { alert('请求失败'); }
};

const openAddIpModal = (ip) => {
  ipToAdd.value = ip.split(':')[0];
  selectedCategory.value = 'whitelists';
  selectedIpList.value = '';
  isAddIpModalOpen.value = true;
};

const confirmAddIpToList = async () => {
  if (!selectedIpList.value) {
    alert('请选择一个IP名单！');
    return;
  }
  try {
    const response = await fetch(getApiUrl(`/api/ip-lists/add`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        category: selectedCategory.value,
        listName: selectedIpList.value,
        ip: ipToAdd.value
      })
    });
    const result = await response.json();
    alert(result.message || result.error);
    if (response.ok) {
      isAddIpModalOpen.value = false;
      fetchIPLists(); // Refresh the lists data
    }
  } catch (error) {
    alert('请求失败');
  }
};


const openAddModal = () => {
  modalMode.value = 'add';
  currentRule.value = {
    Name: '', Protocol: 'tcp', ListenAddr: '', ListenPort: null,
    ForwardAddr: '', ForwardPort: null,
    AccessControl: { Mode: 'disabled', ListName: '' }, Enabled: true,
    RateLimit: 0,
    ConnectionLimit: 256,
    UDPSessionTimeout: 30000,
    UDPMaxSessions: 32,
    UDPMaxBlockLength: 1500,
  };
  uiState.value = { protocolType: 'tcp', ipVersion: 'any' };
  isRuleModalOpen.value = true;
};

const openEditModal = (rule) => {
  modalMode.value = 'edit';
  currentRule.value = Object.assign({
    RateLimit: 0,
    ConnectionLimit: 256,
    UDPSessionTimeout: 30000,
    UDPMaxSessions: 32,
    UDPMaxBlockLength: 1500,
  }, JSON.parse(JSON.stringify(rule)));
  
  let proto = rule.Protocol;
  let version = 'any';

  if (rule.ListenAddr === '0.0.0.0') {
    version = 'ipv4';
  } else if (rule.ListenAddr === '::') {
    version = 'ipv6';
  } else if (rule.ListenAddr === '') {
     if (proto.endsWith('4')) version = 'ipv4';
     if (proto.endsWith('6')) version = 'ipv6';
  }

  if (proto.startsWith('tcp,udp')) {
    proto = 'tcp,udp';
  } else if (proto.startsWith('tcp')) {
    proto = 'tcp';
  } else if (proto.startsWith('udp')) {
    proto = 'udp';
  }
  
  uiState.value = { protocolType: proto, ipVersion: version };
  
  if (currentRule.value.Enabled === undefined) {
    currentRule.value.Enabled = true;
  }
  if (!currentRule.value.AccessControl) {
    currentRule.value.AccessControl = { Mode: 'disabled', ListName: '' };
  }
  originalRuleName.value = rule.Name;
  isRuleModalOpen.value = true;
};

const openConnectionsModal = (rule) => {
  ruleForModal.value = rule.Name;
  connectionsForModal.value = connections.value.filter(c => c.rule === rule.Name);
  isConnModalOpen.value = true;
};

watch(selectedCategory, () => {
    selectedIpList.value = '';
});


onMounted(() => {
  connectWebSocket();
  fetchRules();
  fetchIPLists();
});

onUnmounted(() => {
  if (socket) socket.close();
});
</script>

<template>
  <div>
    <div class="panel rule-overview-panel">
      <div class="panel-header">
        <h2>转发规则管理 ({{ rules ? rules.length : 0 }})</h2>
        <button @click="openAddModal" class="add-rule-btn">+ 添加规则</button>
      </div>
      <div class="rules-container">
        <div v-if="!rules || rules.length === 0" class="empty-state-small">暂无规则...</div>
        <div v-for="rule in rules" :key="rule.Name" class="rule-card" :class="{ 'disabled-rule': !rule.Enabled }">
          <div class="rule-card-top">
            <div class="rule-toggle">
              <label class="switch">
                <input type="checkbox" :checked="rule.Enabled" @click.prevent="toggleRule(rule)">
                <span class="slider round"></span>
              </label>
            </div>
            <div class="rule-actions">
              <button @click="openEditModal(rule)" class="action-btn edit-btn" title="编辑"><IconEdit /></button>
              <button @click="deleteRule(rule.Name)" class="action-btn delete-btn" title="删除"><IconDelete /></button>
            </div>
          </div>
          <div class="rule-name-status">
            <div class="rule-name">{{ rule.Name }}</div>
            <span :class="['status-tag', ruleStatuses[rule.Name]]">
              {{ ruleStatuses[rule.Name] === 'running' ? '运行中' : (ruleStatuses[rule.Name] === 'error' ? '错误' : '已停止') }}
            </span>
          </div>
          <div class="rule-protocol">{{ rule.Protocol.toUpperCase() }}</div>
          <div class="rule-path">
            <span>{{ rule.ListenAddr || '*' }}:{{ rule.ListenPort }}</span>
            <span class="arrow">→</span>
            <span>{{ rule.ForwardAddr }}:{{ rule.ForwardPort }}</span>
          </div>
          <div class="rule-status">
            <div class="status-item connections" @click="openConnectionsModal(rule)">
              <IconLink /><span>实时连接:</span> <span class="count">{{ connectionsCount[rule.Name] || 0 }}</span>
            </div>
            <div 
              class="status-item logs" 
              @mouseenter="showLogTooltip($event, rule)" 
              @mouseleave="hideLogTooltip"
              @click="openLogModal(rule)"
            >
              <IconLogs /> 查看日志
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="isRuleModalOpen" class="modal-overlay" @click.self="isRuleModalOpen = false">
      <div class="modal-content large">
        <h2>{{ modalMode === 'add' ? '添加新规则' : '编辑规则' }}</h2>
        <form @submit.prevent="handleSubmit">
          <div class="form-section">
            <h4>基础配置</h4>
            <div class="form-group"><label for="name">规则名称 (唯一)</label><input id="name" v-model="currentRule.Name" type="text" required placeholder="例如 my-web-proxy"></div>
            <div class="form-row">
              <div class="form-group">
                <label for="protocol">协议类型</label>
                <select id="protocol" v-model="uiState.protocolType">
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="tcp,udp">TCP & UDP</option>
                </select>
              </div>
              <div class="form-group">
                <label for="listen-version">监听 IP 版本</label>
                <select id="listen-version" v-model="uiState.ipVersion">
                    <option value="any">任意 (Any)</option>
                    <option value="ipv4">仅 IPv4</option>
                    <option value="ipv6">仅 IPv6</option>
                </select>
              </div>
            </div>
            <div class="form-row">
                <div class="form-group"><label for="listen-port">监听端口</label><input id="listen-port" v-model.number="currentRule.ListenPort" type="number" required placeholder="例如 8080"></div>
                <div class="form-group"><label for="forward-port">目标端口</label><input id="forward-port" v-model.number="currentRule.ForwardPort" type="number" required placeholder="例如 80"></div>
            </div>
            <div class="form-group"><label for="forward-addr">目标地址</label><input id="forward-addr" v-model="currentRule.ForwardAddr" type="text" required placeholder="例如 192.168.1.100 或 google.com"></div>
          </div>

          <div class="form-section">
            <h4>访问控制</h4>
            <div class="form-row">
                <div class="form-group">
                    <label>访问控制模式</label>
                    <select v-model="currentRule.AccessControl.Mode">
                    <option value="disabled">不启用</option>
                    <option value="whitelist">白名单</option>
                    <option value="blacklist">黑名单</option>
                    </select>
                </div>
                <div class="form-group" v-if="currentRule.AccessControl.Mode !== 'disabled'">
                    <label>选择IP名单</label>
                    <select v-if="currentRule.AccessControl.Mode === 'whitelist'" v-model="currentRule.AccessControl.ListName" required>
                    <option disabled value="">选择白名单或IP集</option>
                    <option v-for="list in availableWhitelists" :key="list.name" :value="list.name">{{ list.name }} ({{ list.source }})</option>
                    </select>
                     <select v-if="currentRule.AccessControl.Mode === 'blacklist'" v-model="currentRule.AccessControl.ListName" required>
                    <option disabled value="">选择黑名单或IP集</option>
                    <option v-for="list in availableBlacklists" :key="list.name" :value="list.name">{{ list.name }} ({{ list.source }})</option>
                    </select>
                </div>
            </div>
          </div>
          
          <div class="form-section" v-if="uiState.protocolType.includes('tcp')">
            <h4>TCP 设置</h4>
            <div class="form-row">
                <div class="form-group">
                    <label for="rate-limit">端口限速 (KB/s)</label>
                    <input id="rate-limit" v-model.number="currentRule.RateLimit" type="number" placeholder="0 表示不限速">
                </div>
                <div class="form-group">
                    <label for="conn-limit">单端口连接数限制</label>
                    <input id="conn-limit" v-model.number="currentRule.ConnectionLimit" type="number" placeholder="默认 256">
                </div>
            </div>
          </div>

          <div class="form-section" v-if="uiState.protocolType.includes('udp')">
            <h4>UDP 设置</h4>
            <div class="form-row">
                <div class="form-group">
                    <label for="udp-timeout">会话超时 (毫秒)</label>
                    <input id="udp-timeout" v-model.number="currentRule.UDPSessionTimeout" type="number" placeholder="默认 30000">
                </div>
                <div class="form-group">
                    <label for="udp-sessions">最大会话数</label>
                    <input id="udp-sessions" v-model.number="currentRule.UDPMaxSessions" type="number" placeholder="默认 32">
                </div>
            </div>
            <div class="form-group">
                <label for="udp-block">最大块长度 (字节)</label>
                <input id="udp-block" v-model.number="currentRule.UDPMaxBlockLength" type="number" placeholder="默认 1500">
            </div>
          </div>

          <div class="form-actions"><button type="button" class="btn-cancel" @click="isRuleModalOpen = false">取消</button><button type="submit" class="btn-save">保存规则</button></div>
        </form>
      </div>
    </div>

    <div v-if="isConnModalOpen" class="modal-overlay" @click.self="isConnModalOpen = false">
      <div class="modal-content large">
        <h2>实时连接: {{ ruleForModal }}</h2>
        <div v-if="connectionsForModal.length === 0" class="empty-state-small">此规则下暂无活动连接</div>
        <table v-else>
          <thead>
            <tr>
              <th>客户端地址</th>
              <th>目标地址</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="conn in connectionsForModal" :key="conn.id">
              <td>{{ conn.clientAddr }}</td>
              <td>{{ conn.targetAddr }}</td>
              <td class="conn-actions">
                <button @click="disconnectConnection(conn.id)" class="btn-disconnect" title="断开此连接">断开</button>
                <div class="dropdown">
                  <button class="btn-add-list">加入名单</button>
                  <div class="dropdown-content">
                    <a @click="openAddIpModal(conn.clientAddr)">加入IP名单...</a>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    
    <div v-if="isLogModalOpen" class="modal-overlay" @click.self="isLogModalOpen = false">
      <div class="modal-content large">
        <h2>日志: {{ ruleForLogModal }}</h2>
        <div v-if="isLoadingLogs" class="empty-state-small">加载中...</div>
        <pre v-else class="logs-container-modal">{{ logsForModal.join('\n') }}</pre>
        <div class="pagination-controls">
           <select v-model="logModalPageSize" @change="loadModalLogs">
                <option :value="20">20/页</option>
                <option :value="50">50/页</option>
                <option :value="100">100/页</option>
            </select>
            <button @click="logModalCurrentPage > 1 && (logModalCurrentPage--, loadModalLogs())" :disabled="logModalCurrentPage <= 1">上一页</button>
            <div class="page-jump">
                第
                <input type="number" v-model.number="logModalJumpToPage" @keyup.enter="handleModalJump" min="1" :max="logModalTotalPages">
                / {{ logModalTotalPages }} 页
            </div>
            <button @click="logModalCurrentPage < logModalTotalPages && (logModalCurrentPage++, loadModalLogs())" :disabled="logModalCurrentPage >= logModalTotalPages">下一页</button>
        </div>
      </div>
    </div>
    
    <div 
      v-if="isTooltipVisible" 
      ref="tooltipRef" 
      class="tooltip" 
      :style="{ top: tooltipTop + 'px', left: tooltipLeft + 'px' }"
      @mouseenter="cancelTooltipHide"
      @mouseleave="hideLogTooltip">
      <pre>{{ tooltipContent.join('\n') }}</pre>
       <div class="pagination-controls tooltip-pagination">
            <select v-model="tooltipPageSize" @change="loadTooltipLogs">
                <option :value="10">10/页</option>
                <option :value="20">20/页</option>
                <option :value="50">50/页</option>
            </select>
            <button @click="tooltipCurrentPage > 1 && (tooltipCurrentPage--, loadTooltipLogs())" :disabled="tooltipCurrentPage <= 1">‹</button>
            <div class="page-jump-tooltip">
                <input type="number" v-model.number="tooltipJumpToPage" @keyup.enter="handleTooltipJump" min="1" :max="tooltipTotalPages">
                <span>/{{ tooltipTotalPages }}</span>
            </div>
            <button @click="tooltipCurrentPage < tooltipTotalPages && (tooltipCurrentPage++, loadTooltipLogs())" :disabled="tooltipCurrentPage >= tooltipTotalPages">›</button>
        </div>
    </div>

     <div v-if="isAddIpModalOpen" class="modal-overlay" @click.self="isAddIpModalOpen = false">
        <div class="modal-content">
            <h2>添加到IP名单</h2>
            <p>将 IP <strong>{{ ipToAdd }}</strong> 添加到...</p>
            <div class="form-row">
                <div class="form-group">
                <label for="ip-list-category-select">名单分类</label>
                <select id="ip-list-category-select" v-model="selectedCategory">
                    <option value="whitelists">IP白名单</option>
                    <option value="blacklists">IP黑名单</option>
                    <option value="ip_sets">IP集 (通用)</option>
                </select>
                </div>
                <div class="form-group">
                <label for="ip-list-select">选择一个IP名单</label>
                <select id="ip-list-select" v-model="selectedIpList" :disabled="!selectedCategory">
                    <option disabled value="">请选择...</option>
                    <option v-for="(ips, name) in availableListsForCategory" :key="name" :value="name">
                    {{ name }}
                    </option>
                </select>
                </div>
            </div>
            <div class="form-actions">
            <button type="button" class="btn-cancel" @click="isAddIpModalOpen = false">取消</button>
            <button type="button" class="btn-save" @click="confirmAddIpToList">确认添加</button>
            </div>
        </div>
    </div>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.panel-header h2 { margin-top: 0; font-size: 1.2rem; }
.add-rule-btn { background-color: #007bff; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; font-size: 0.9rem; transition: background-color 0.2s; }
.add-rule-btn:hover { background-color: #0056b3; }
.rules-container { display: flex; flex-wrap: wrap; gap: 1rem; }
.rule-card { border: 1px solid #e0e0e0; border-radius: 6px; padding: 1rem; flex-basis: 280px; position: relative; display: flex; flex-direction: column; }
.rule-card-top { display: flex; justify-content: space-between; align-items: center; height: 22px; margin-bottom: 0.75rem; }
.rule-actions { display: flex; gap: 0.3rem; opacity: 0; transition: opacity 0.2s; }
.rule-card:hover .rule-actions { opacity: 1; }
.rule-name { font-weight: 600; font-size: 1.1rem; }
.rule-protocol { background-color: #e7f3ff; color: #0069d9; font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; margin-top: 0.5rem; align-self: flex-start; }
.action-btn { background: none; border: none; cursor: pointer; font-size: 1rem; padding: 0.3rem; display: inline-flex; align-items: center; justify-content: center; }
.action-btn:hover { background-color: #e0e0e0; border-radius: 3px;}
.rule-path { display: flex; align-items: center; gap: 0.5rem; font-family: monospace; font-size: 1.1rem; margin-top: 0.75rem;}
.rule-path .arrow { color: #007bff; font-weight: bold; }
.rule-status { border-top: 1px solid #f0f0f0; margin-top: auto; padding-top: 1rem; display: flex; justify-content: space-between; font-size: 0.9rem; }
.status-item { cursor: pointer; color: #555; text-decoration: none; display: flex; align-items: center; gap: 6px; }
.status-item:hover { color: #007bff; }
.status-item .count { font-weight: bold; background-color: #e7f3ff; padding: 2px 6px; border-radius: 5px; }
.status-item svg { vertical-align: middle; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6); display: flex; justify-content: center; align-items: flex-start; padding: 5vh 1rem; z-index: 1000; overflow-y: auto; box-sizing: border-box; }
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 100%; max-width: 600px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); margin-bottom: 5vh; }
.modal-content.large { max-width: 800px; }
.modal-content h2 { margin-top: 0; margin-bottom: 1.5rem; }
.form-group { margin-bottom: 1rem; flex: 1; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.form-group input, .form-group select { width: 100%; padding: 0.7rem; border: 1px solid #e0e0e0; border-radius: 5px; font-size: 1rem; box-sizing: border-box; }
.form-actions { margin-top: 2rem; display: flex; justify-content: flex-end; gap: 1rem; }
.form-actions button { padding: 0.7rem 1.5rem; border-radius: 5px; border: none; cursor: pointer; font-size: 1rem; font-weight: 500; }
.btn-cancel { background-color: #e0e0e0; color: #333; }
.btn-save { background-color: #007bff; color: white; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.8rem 1rem; text-align: left; border-bottom: 1px solid #e0e0e0; font-size: 0.9rem; }
th { background-color: #f9fafb; font-weight: 600; }
.conn-actions { display: flex; gap: 10px; align-items: center; }
.btn-disconnect { background-color: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }
.btn-add-list { background-color: #6c757d; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }
.dropdown { position: relative; display: inline-block; }
.dropdown-content { display: none; position: absolute; background-color: #f9f9f9; min-width: 120px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 10; border-radius: 5px; right: 0; }
.dropdown-content a { color: black; padding: 8px 12px; text-decoration: none; display: block; cursor: pointer; }
.dropdown-content a:hover { background-color: #f1f1f1; }
.dropdown:hover .dropdown-content { display: block; }
.rule-card.disabled-rule { background-color: #f8f9fa; opacity: 0.6; }
.rule-card.disabled-rule .rule-name, .rule-card.disabled-rule .rule-path { text-decoration: line-through; }
.switch { position: relative; display: inline-block; width: 40px; height: 22px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; }
.slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .4s; }
input:checked + .slider { background-color: #28a745; }
input:focus + .slider { box-shadow: 0 0 1px #28a745; }
input:checked + .slider:before { transform: translateX(18px); }
.slider.round { border-radius: 22px; }
.slider.round:before { border-radius: 50%; }
.form-row { display: flex; gap: 1rem; }
.form-section { border: 1px solid #f0f0f0; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
.form-section h4 { margin-top: 0; margin-bottom: 1rem; border-bottom: 1px solid #eee; padding-bottom: 0.75rem; font-size: 1.1rem; color: #333; }
.rule-name-status { display: flex; align-items: center; gap: 10px; margin-bottom: 0.5rem; }
.status-tag { padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 500; }
.status-tag.running { background-color: #d4edda; color: #155724; }
.status-tag.stopped { background-color: #e2e3e5; color: #383d41; }
.status-tag.error { background-color: #f8d7da; color: #721c24; }
.logs-container-modal {
  background-color: #282c34;
  color: #dcdfe4;
  border-radius: 5px;
  height: 65vh;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: "SFMono-Regular", Consolas, Menlo, monospace;
  font-size: 0.85rem;
  padding: 1rem;
  margin-bottom: 1rem;
}

.tooltip {
  position: fixed;
  background-color: rgba(40, 44, 52, 0.95);
  color: #dcdfe4;
  border: 1px solid #555;
  border-radius: 5px;
  padding: 0.75rem;
  font-family: "SFMono-Regular", Consolas, Menlo, monospace;
  font-size: 0.75rem;
  white-space: pre;
  z-index: 2000;
  max-width: 800px;
  overflow: hidden;
  pointer-events: auto;
  display: flex;
  flex-direction: column;
  transition: opacity 0.2s;
}

.tooltip pre {
  margin: 0;
  padding: 0;
  flex-grow: 1;
  max-height: 250px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.pagination-controls {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
    padding-top: 10px;
    margin-top: auto;
    border-top: 1px solid #555;
    font-size: 0.8rem;
}
.pagination-controls button, .pagination-controls select {
    background-color: #4a5568;
    color: white;
    border: 1px solid #718096;
    border-radius: 4px;
    padding: 2px 8px;
    cursor: pointer;
}
.pagination-controls button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}
.tooltip-pagination {
    font-size: 0.7rem;
    padding-top: 5px;
    margin-top: 5px;
    gap: 5px;
}
.tooltip-pagination button, .tooltip-pagination select {
    padding: 1px 5px;
}
.modal-content .pagination-controls {
    border-top: 1px solid #e0e0e0;
}
.modal-content .pagination-controls button, .modal-content .pagination-controls select {
    background-color: #f8f9fa;
    color: #333;
    border: 1px solid #ccc;
}
.page-jump, .page-jump-tooltip {
    display: flex;
    align-items: center;
    gap: 5px;
}
.page-jump input, .page-jump-tooltip input {
    width: 40px;
    text-align: center;
    padding: 2px;
    border-radius: 3px;
    border: 1px solid #718096;
    background-color: #2d3748;
    color: white;
}
.modal-content .page-jump input {
    width: 50px;
    padding: 0.5rem;
    border: 1px solid #ccc;
    background-color: white;
    color: black;
}
.page-jump input::-webkit-outer-spin-button,
.page-jump input::-webkit-inner-spin-button,
.page-jump-tooltip input::-webkit-outer-spin-button,
.page-jump-tooltip input::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
.page-jump input[type=number],
.page-jump-tooltip input[type=number] {
  -moz-appearance: textfield;
}
</style>