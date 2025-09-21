<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue';

const rules = ref([]);
const ipLists = ref({});
const connections = ref([]);
const isRuleModalOpen = ref(false);
const isConnModalOpen = ref(false);
const modalMode = ref('add');
const currentRule = ref({ Name: '', Protocol: 'tcp', ListenPort: null, ForwardAddr: '', ForwardPort: null, AccessControl: { Mode: 'disabled', ListName: '' } });
const originalRuleName = ref('');
const connectionsForModal = ref([]);
const ruleForModal = ref('');
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
        if (isConnModalOpen.value) {
          connectionsForModal.value = payload.connections.filter(c => c.Rule === ruleForModal.value);
        }
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
  const url = modalMode.value === 'add' ? getApiUrl('/api/rules') : getApiUrl(`/api/rules/${originalRuleName.value}`);
  const method = modalMode.value === 'add' ? 'POST' : 'PUT';
  const payload = { ...currentRule.value, ListenPort: parseInt(currentRule.value.ListenPort, 10), ForwardPort: parseInt(currentRule.value.ForwardPort, 10) };
  try {
    const response = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
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

const addIpToList = async (ip, listType) => {
  const clientIP = ip.split(':')[0];
  const listName = prompt(`请输入要将IP(${clientIP})添加到的${listType}名单的名称:`);
  if (!listName) return;

  try {
    const response = await fetch(getApiUrl(`/api/ip-lists/${listName}/add`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: clientIP })
    });
    const result = await response.json();
    alert(result.message || result.error);
  } catch (error) { alert('请求失败'); }
};

const openAddModal = () => {
  modalMode.value = 'add';
  currentRule.value = { Name: '', Protocol: 'tcp', ListenPort: null, ForwardAddr: '', ForwardPort: null, AccessControl: { Mode: 'disabled', ListName: '' } };
  isRuleModalOpen.value = true;
};

const openEditModal = (rule) => {
  modalMode.value = 'edit';
  currentRule.value = JSON.parse(JSON.stringify(rule));
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
        <div v-for="rule in rules" :key="rule.Name" class="rule-card">
          <div class="rule-actions">
            <button @click="openEditModal(rule)" class="action-btn edit-btn" title="编辑">✏️</button>
            <button @click="deleteRule(rule.Name)" class="action-btn delete-btn" title="删除">🗑️</button>
          </div>
          <div class="rule-name">{{ rule.Name }}</div>
          <div class="rule-path">
            <span>{{ rule.ListenPort }}</span>
            <span class="arrow">→</span>
            <span>{{ rule.ForwardAddr }}:{{ rule.ForwardPort }}</span>
          </div>
          <div class="rule-protocol">{{ rule.Protocol.toUpperCase() }}</div>
          <div class="rule-status">
            <div class="status-item connections" @click="openConnectionsModal(rule)">
              <span>🔗 实时连接:</span> <span class="count">{{ connectionsCount[rule.Name] || 0 }}</span>
            </div>
            <router-link :to="{ path: '/logs', query: { rule: rule.Name } }" class="status-item logs">
              📜 查看日志
            </router-link>
          </div>
        </div>
      </div>
    </div>

    <div v-if="isRuleModalOpen" class="modal-overlay" @click.self="isRuleModalOpen = false">
      <div class="modal-content">
        <h2>{{ modalMode === 'add' ? '添加新规则' : '编辑规则' }}</h2>
        <form @submit.prevent="handleSubmit">
          <div class="form-group"><label for="name">规则名称 (唯一)</label><input id="name" v-model="currentRule.Name" :disabled="modalMode === 'edit'" type="text" required placeholder="例如 my-web-proxy"></div>
          <div class="form-group"><label for="protocol">协议</label><select id="protocol" v-model="currentRule.Protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></div>
          <div class="form-group"><label for="listen-port">监听端口</label><input id="listen-port" v-model.number="currentRule.ListenPort" type="number" required placeholder="例如 8080"></div>
          <div class="form-group"><label for="forward-addr">目标地址</label><input id="forward-addr" v-model="currentRule.ForwardAddr" type="text" required placeholder="例如 192.168.1.100 或 localhost"></div>
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
                    <a @click="addIpToList(conn.ClientAddr, '白名单')">加入白名单...</a>
                    <a @click="addIpToList(conn.ClientAddr, '黑名单')">加入黑名单...</a>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
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
.rule-actions { position: absolute; top: 0.2rem; right: 0.2rem; display: flex; gap: 0.3rem; background-color: rgba(255,255,255,0.8); border-radius: 5px; padding: 2px; opacity: 0; transition: opacity 0.2s; }
.rule-card:hover .rule-actions { opacity: 1; }
.action-btn { background: none; border: none; cursor: pointer; font-size: 1rem; padding: 0.3rem; }
.action-btn:hover { background-color: #e0e0e0; border-radius: 3px;}
.rule-name { font-weight: 600; margin-bottom: 0.5rem; }
.rule-path { display: flex; align-items: center; gap: 0.5rem; font-family: monospace; font-size: 1.1rem; }
.rule-path .arrow { color: #007bff; font-weight: bold; }
.rule-protocol { position: absolute; top: 0.5rem; right: 3.5rem; background-color: #e7f3ff; color: #0069d9; font-size: 0.75rem; padding: 2px 6px; border-radius: 4px; }
.rule-status { border-top: 1px solid #f0f0f0; margin-top: auto; padding-top: 1rem; display: flex; justify-content: space-between; font-size: 0.9rem; }
.status-item { cursor: pointer; color: #555; text-decoration: none; display: flex; align-items: center; gap: 6px; }
.status-item:hover { color: #007bff; }
.status-item .count { font-weight: bold; background-color: #e7f3ff; padding: 2px 6px; border-radius: 5px; }
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
</style>
