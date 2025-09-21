<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue';
import IconEdit from '../components/icons/IconEdit.vue';
import IconDelete from '../components/icons/IconDelete.vue';
import IconLink from '../components/icons/IconLink.vue';
import IconLogs from '../components/icons/IconLogs.vue';

const rules = ref([]);
const ipLists = ref({});
const connections = ref([]);
const recentLogsByRule = ref({});

// --- Modal States ---
const isRuleModalOpen = ref(false);
const isConnModalOpen = ref(false);
const isLogModalOpen = ref(false);
const isAddIpModalOpen = ref(false);

// --- Tooltip States ---
const isTooltipVisible = ref(false);
const tooltipContent = ref('');
const tooltipTop = ref(0);
const tooltipLeft = ref(0);

// --- Modal Content States ---
const modalMode = ref('add');
const uiState = ref({
  protocolType: 'tcp',
  ipVersion: 'any',
});
const currentRule = ref({
  Name: '', Protocol: 'tcp', ListenAddr: '', ListenPort: null,
  ForwardAddr: '', ForwardPort: null,
  AccessControl: { Mode: 'disabled', ListName: '' }, Enabled: true,
});
const originalRuleName = ref('');
const connectionsForModal = ref([]);
const ruleForModal = ref('');
const logsForModal = ref('');
const ruleForLogModal = ref('');
const isLoadingLogs = ref(false);

// --- Add IP to List Modal State ---
const ipToAdd = ref('');
const listTypeToAdd = ref('');
const selectedIpList = ref('');

let socket = null;

const connectionsCount = computed(() => {
  const counts = {};
  if (rules.value) {
    for (const rule of rules.value) {
      counts[rule.Name] = connections.value.filter(c => c.Rule === rule.Name).length;
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
        connectionsForModal.value = payload.connections.filter(c => c.Rule === ruleForModal.value);
      }
    } catch (e) { console.error("解析WebSocket数据失败:", e); }
  };
  socket.onclose = () => setTimeout(connectWebSocket, 3000);
};

const fetchRules = async () => {
  try {
    const response = await fetch(getApiUrl('/api/rules'));
    if (response.ok) { rules.value = await response.json() || []; }
  } catch (error) { console.error('加载规则列表失败:', error); }
};

const fetchIPLists = async () => {
  try {
    const response = await fetch(getApiUrl('/api/ip-lists'));
    if (response.ok) { ipLists.value = await response.json() || {}; }
  } catch (error) { console.error('加载IP名单失败:', error); }
};

const triggerRestart = async () => {
  try { await fetch(getApiUrl('/api/actions/restart'), { method: 'POST' }); }
  catch (error) { console.error('重启请求发送失败:', error); }
};

const toggleRule = async (rule) => {
  try {
    const response = await fetch(getApiUrl(`/api/rules/${rule.Name}/toggle`), { method: 'POST' });
    const result = await response.json();
    if (response.ok) {
      rule.Enabled = result.enabled;
      if (confirm(`规则 '${rule.Name}' 状态已切换。\n是否立即重启服务以应用更改？`)) {
        triggerRestart();
        alert('重启命令已发送。请稍后刷新页面。');
      }
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
      fetchRules();
      if (confirm(result.message + '\n是否立即重启服务以应用更改？')) {
        triggerRestart();
        alert('重启命令已发送。请稍后刷新页面。');
      }
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
    ListenPort: parseInt(currentRule.value.ListenPort, 10),
    ForwardPort: parseInt(currentRule.value.ForwardPort, 10),
    Protocol: buildProtocolString(),
    ListenAddr: listenAddrMap[uiState.value.ipVersion]
  };

  const url = modalMode.value === 'add' ? getApiUrl('/api/rules') : getApiUrl(`/api/rules/${originalRuleName.value}`);
  const method = modalMode.value === 'add' ? 'POST' : 'PUT';

  try {
    const response = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(finalRule) });
    const result = await response.json();
    if (response.ok) {
      isRuleModalOpen.value = false;
      fetchRules();
      if (confirm(`规则已成功 ${modalMode.value === 'add' ? '添加' : '更新'}！\n是否立即重启服务以应用更改？`)) {
        triggerRestart();
        alert('重启命令已发送。请稍后刷新页面。');
      }
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

const openAddIpModal = (ip, listType) => {
  ipToAdd.value = ip.split(':')[0];
  listTypeToAdd.value = listType;
  selectedIpList.value = '';
  isAddIpModalOpen.value = true;
};

const confirmAddIpToList = async () => {
  if (!selectedIpList.value) {
    alert('请选择一个IP名单！');
    return;
  }
  try {
    const response = await fetch(getApiUrl(`/api/ip-lists/${selectedIpList.value}/add`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ipToAdd.value })
    });
    const result = await response.json();
    alert(result.message || result.error);
    if (response.ok) {
      isAddIpModalOpen.value = false;
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
  };
  uiState.value = { protocolType: 'tcp', ipVersion: 'any' };
  isRuleModalOpen.value = true;
};

const openEditModal = (rule) => {
  modalMode.value = 'edit';
  currentRule.value = JSON.parse(JSON.stringify(rule));
  
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
  connectionsForModal.value = connections.value.filter(c => c.Rule === rule.Name);
  isConnModalOpen.value = true;
};

const openLogModal = async (rule) => {
  ruleForLogModal.value = rule.Name;
  isLogModalOpen.value = true;
  isLoadingLogs.value = true;
  logsForModal.value = '正在加载完整的日志...';
  try {
    const response = await fetch(getApiUrl(`/api/logs?rule=${rule.Name}`));
    if (response.ok) {
      const logs = await response.text();
      logsForModal.value = logs ? logs.split('\n').reverse().join('\n') : '该规则下暂无日志记录。';
    } else {
      logsForModal.value = `加载日志失败: ${response.statusText}`;
    }
  } catch (error) {
    logsForModal.value = '加载失败，无法连接到API。';
  } finally {
    isLoadingLogs.value = false;
  }
};

const showLogTooltip = (event, rule) => {
  const logs = recentLogsByRule.value[rule.Name];
  if (logs && logs.length > 0) {
    tooltipContent.value = logs.slice(-5).reverse().join('\n');
    isTooltipVisible.value = true;
    const rect = event.target.getBoundingClientRect();
    tooltipTop.value = rect.bottom + 10;
    tooltipLeft.value = rect.left;
  }
};

const hideLogTooltip = () => {
  isTooltipVisible.value = false;
};

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
          <div class="rule-name">{{ rule.Name }}</div>
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
              @click="openLogModal(rule)" 
              @mouseenter="showLogTooltip($event, rule)" 
              @mouseleave="hideLogTooltip"
            >
              <IconLogs /> 查看日志
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="isRuleModalOpen" class="modal-overlay" @click.self="isRuleModalOpen = false">
      <div class="modal-content">
        <h2>{{ modalMode === 'add' ? '添加新规则' : '编辑规则' }}</h2>
        <form @submit.prevent="handleSubmit">
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

          <div class="form-group"><label for="listen-port">监听端口</label><input id="listen-port" v-model.number="currentRule.ListenPort" type="number" required placeholder="例如 8080"></div>
          <div class="form-group"><label for="forward-addr">目标地址</label><input id="forward-addr" v-model="currentRule.ForwardAddr" type="text" required placeholder="例如 192.168.1.100 或 google.com"></div>
          <div class="form-group"><label for="forward-port">目标端口</label><input id="forward-port" v-model.number="currentRule.ForwardPort" type="number" required placeholder="例如 80"></div>
          
          <hr class="form-divider">
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
            <select v-model="currentRule.AccessControl.ListName" required>
              <option disabled value="">请选择一个IP名单</option>
              <option v-for="(ips, name) in ipLists" :key="name" :value="name">{{ name }}</option>
            </select>
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
            <tr v-for="conn in connectionsForModal" :key="conn.ID">
              <td>{{ conn.ClientAddr }}</td>
              <td>{{ conn.TargetAddr }}</td>
              <td class="conn-actions">
                <button @click="disconnectConnection(conn.ID)" class="btn-disconnect" title="断开此连接">断开</button>
                <div class="dropdown">
                  <button class="btn-add-list">加入名单</button>
                  <div class="dropdown-content">
                    <a @click="openAddIpModal(conn.ClientAddr, '白名单')">加入白名单...</a>
                    <a @click="openAddIpModal(conn.ClientAddr, '黑名单')">加入黑名单...</a>
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
        <pre v-else class="logs-container">{{ logsForModal }}</pre>
      </div>
    </div>
    
    <div v-if="isTooltipVisible" class="tooltip" :style="{ top: tooltipTop + 'px', left: tooltipLeft + 'px' }">
      <pre>{{ tooltipContent }}</pre>
    </div>

    <div v-if="isAddIpModalOpen" class="modal-overlay" @click.self="isAddIpModalOpen = false">
      <div class="modal-content">
        <h2>添加到 {{ listTypeToAdd }}</h2>
        <p>将 IP <strong>{{ ipToAdd }}</strong> 添加到以下哪个名单？</p>
        <div class="form-group">
          <label for="ip-list-select">选择一个IP名单</label>
          <select id="ip-list-select" v-model="selectedIpList">
            <option disabled value="">请选择...</option>
            <option v-for="(ips, name) in ipLists" :key="name" :value="name">
              {{ name }}
            </option>
          </select>
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
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 100%; max-width: 500px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); margin-bottom: 5vh; }
.modal-content.large { max-width: 800px; }
.modal-content h2 { margin-top: 0; margin-bottom: 1.5rem; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.form-group input, .form-group select { width: 100%; padding: 0.7rem; border: 1px solid #e0e0e0; border-radius: 5px; font-size: 1rem; box-sizing: border-box; }
.form-actions { margin-top: 2rem; display: flex; justify-content: flex-end; gap: 1rem; }
.form-actions button { padding: 0.7rem 1.5rem; border-radius: 5px; border: none; cursor: pointer; font-size: 1rem; font-weight: 500; }
.btn-cancel { background-color: #e0e0e0; color: #333; }
.btn-save { background-color: #007bff; color: white; }
.form-divider { border: none; border-top: 1px solid #eee; margin: 1.5rem 0; }
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
.form-row .form-group { flex: 1; }

.logs-container {
  background-color: #282c34;
  color: #dcdfe4;
  border-radius: 5px;
  height: 60vh;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: "SFMono-Regular", Consolas, Menlo, monospace;
  font-size: 0.85rem;
  padding: 1rem;
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
  max-height: 200px;
  overflow: hidden;
  pointer-events: none;
}
</style>