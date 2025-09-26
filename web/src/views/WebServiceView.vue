<script setup>
import { ref, onMounted, onUnmounted, computed, nextTick, watch } from 'vue';
import IconEdit from '../components/icons/IconEdit.vue';
import IconDelete from '../components/icons/IconDelete.vue';
import IconLink from '../components/icons/IconLink.vue';
import IconLogs from '../components/icons/IconLogs.vue';

// --- Main Rule State ---
const webRules = ref([]);
const isMainModalOpen = ref(false);
const mainModalMode = ref('add');
const currentMainRule = ref({});
const originalMainRuleName = ref('');
const ruleStatuses = ref({});

// --- Sub Rule State ---
const isSubModalOpen = ref(false);
const subModalMode = ref('add');
const currentSubRule = ref({});
const originalSubRuleName = ref('');

// --- IP Lists State ---
const ipLists = ref({ whitelists: {}, blacklists: {}, ip_sets: {}, country_ip_lists: {}, url_ip_sets: {} });

// --- WAF State ---
const wafRuleSets = ref([]);

// --- Real-time Data State ---
const connections = ref([]);
const connectionsForModal = ref([]);
const isConnModalOpen = ref(false);
const ruleForConnModal = ref({});

// --- Add IP to List Modal State ---
const isAddIpModalOpen = ref(false);
const ipToAdd = ref('');
const selectedCategory = ref('whitelists');
const selectedIpList = ref('');


const connectionsCount = computed(() => {
    const counts = {};
    if (webRules.value) {
        for (const rule of webRules.value) {
            counts[rule.Name] = connections.value.filter(c => c.rule === rule.Name).length;
            if (rule.SubRules) {
                for (const subRule of rule.SubRules) {
                    const key = `${rule.Name}-${subRule.Name}`;
                    counts[key] = connections.value.filter(c => c.rule === rule.Name && c.sub_rule === subRule.Name).length;
                }
            }
        }
    }
    return counts;
});

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


watch(() => currentMainRule.value?.TLS?.MinVersion, (newVersion) => {
    if (newVersion !== 'TLS1.3' && currentMainRule.value?.TLS) {
        currentMainRule.value.TLS.HTTP3Enabled = false;
    }
});


// --- Log Tooltip State ---
const tooltipRef = ref(null);
const isTooltipVisible = ref(false);
const tooltipContent = ref([]);
const tooltipTop = ref(0);
const tooltipLeft = ref(0);
let hideTooltipTimeout = null;
const tooltipCurrentPage = ref(1);
const tooltipTotalPages = ref(1);
const tooltipRuleName = ref('');
const tooltipPageSize = ref(10);
const tooltipJumpToPage = ref(1);


// --- Log Modal State ---
const isLogModalOpen = ref(false);
const logsForModal = ref([]);
const ruleForLogModal = ref('');
const isLoadingLogs = ref(false);
const logModalCurrentPage = ref(1);
const logModalPageSize = ref(50);
const logModalTotalPages = ref(1);
const logModalJumpToPage = ref(1);

const availableListsForCategory = computed(() => {
    if (!selectedCategory.value || !ipLists.value[selectedCategory.value]) {
        return {};
    }
    return ipLists.value[selectedCategory.value];
});

const getListenAddressDisplay = (rule) => {
    if (rule.ListenAddr) {
        return `${rule.ListenAddr}:${rule.ListenPort}`;
    }
    if (rule.ListenIPv4 && rule.ListenIPv6) {
        return `IPv4/IPv6 : ${rule.ListenPort}`;
    }
    if (rule.ListenIPv4) {
        return `IPv4 : ${rule.ListenPort}`;
    }
    if (rule.ListenIPv6) {
        return `IPv6 : ${rule.ListenPort}`;
    }
    return `未监听 : ${rule.ListenPort}`;
};


let socket = null;
const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

// --- WebSocket Logic ---
const connectWebSocket = () => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${wsProtocol}//${window.location.hostname}:8080/ws`);
  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.connections !== undefined) {
        connections.value = payload.connections;
        if (isConnModalOpen.value) {
            updateConnectionsForModal();
        }
      }
    } catch (e) { console.error("解析WebSocket数据失败:", e); }
  };
  socket.onclose = () => setTimeout(connectWebSocket, 3000);
};


// --- API Fetching Logic ---
const fetchWafRuleSets = async () => {
  try {
    const response = await fetch(getApiUrl('/api/waf/rulesets'));
    if (response.ok) {
      wafRuleSets.value = await response.json() || [];
    }
  } catch (error) {
    console.error('加载 WAF 规则集失败:', error);
  }
};

const fetchRuleStatuses = async () => {
    try {
        const response = await fetch(getApiUrl('/api/web-rules/status'));
        if(response.ok) {
            ruleStatuses.value = await response.json();
        }
    } catch (error) {
        console.error('获取规则状态失败:', error);
    }
};

const fetchWebRules = async () => {
    try {
        const response = await fetch(getApiUrl('/api/web-rules'));
        if (response.ok) {
            webRules.value = await response.json() || [];
            await fetchRuleStatuses();
        }
    } catch (error) { console.error('加载Web服务规则失败:', error); }
};

const fetchIPLists = async () => {
    try {
        const response = await fetch(getApiUrl('/api/ip-lists'));
        if (response.ok) {
            const data = await response.json();
            ipLists.value = data || {};
        }
    } catch (error) { console.error('加载IP名单失败:', error); }
};

const fetchPaginatedLogs = async (ruleName, page, pageSize) => {
    const response = await fetch(getApiUrl(`/api/logs?rule=${ruleName}&page=${page}&pageSize=${pageSize}`));
    if (!response.ok) throw new Error('Failed to fetch logs');
    return await response.json();
}

// --- Log Display Logic ---
const showLogTooltip = async (event, ruleName) => {
    clearTimeout(hideTooltipTimeout);
    tooltipRuleName.value = ruleName;
    tooltipCurrentPage.value = 1;
    isTooltipVisible.value = true;
    tooltipContent.value = ["加载中..."];

    await nextTick();
    positionTooltip(event);
    await loadTooltipLogs();
};

const loadTooltipLogs = async () => {
    try {
        const data = await fetchPaginatedLogs(tooltipRuleName.value, tooltipCurrentPage.value, tooltipPageSize.value);
        tooltipContent.value = data.logs.length > 0 ? data.logs : ['暂无日志记录'];
        tooltipTotalPages.value = data.totalPages;
        tooltipJumpToPage.value = tooltipCurrentPage.value;
    } catch (e) {
        tooltipContent.value = ['日志加载失败'];
    }
};

const handleTooltipJump = () => {
    const page = parseInt(tooltipJumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= tooltipTotalPages.value) {
        tooltipCurrentPage.value = page;
        loadTooltipLogs();
    } else {
        tooltipJumpToPage.value = tooltipCurrentPage.value;
    }
}

const positionTooltip = (event) => {
    if (!tooltipRef.value) return;

    const rect = event.currentTarget.getBoundingClientRect();
    const tooltipHeight = tooltipRef.value.offsetHeight;
    const tooltipWidth = tooltipRef.value.offsetWidth;

    let top = rect.bottom + 10;
    let left = rect.left;

    if (top + tooltipHeight > window.innerHeight) {
        top = rect.top - tooltipHeight - 10;
    }
    if (left + tooltipWidth > window.innerWidth) {
        left = window.innerWidth - tooltipWidth - 10;
    }
    if (left < 10) {
        left = 10;
    }

    tooltipTop.value = top;
    tooltipLeft.value = left;
};

const hideLogTooltip = () => {
    hideTooltipTimeout = setTimeout(() => { isTooltipVisible.value = false; }, 200);
};
const cancelTooltipHide = () => clearTimeout(hideTooltipTimeout);

const handleViewDetailsClick = (ruleName) => {
    isTooltipVisible.value = false;
    clearTimeout(hideTooltipTimeout);
    openLogModal(ruleName);
};

const openLogModal = async (ruleName) => {
  ruleForLogModal.value = ruleName;
  isLogModalOpen.value = true;
  logModalCurrentPage.value = 1;
  await loadModalLogs();
};

const loadModalLogs = async () => {
    isLoadingLogs.value = true;
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

// --- Connection Modal Logic ---
const openConnectionsModal = (ruleName, subRuleName = null) => {
    ruleForConnModal.value = { main: ruleName, sub: subRuleName };
    updateConnectionsForModal();
    isConnModalOpen.value = true;
};

const updateConnectionsForModal = () => {
    const { main, sub } = ruleForConnModal.value;
    if (sub === null) {
        connectionsForModal.value = connections.value.filter(c => c.rule === main);
    } else {
        connectionsForModal.value = connections.value.filter(c => c.rule === main && c.sub_rule === sub);
    }
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
      fetchIPLists();
    }
  } catch (error) {
    alert('请求失败');
  }
};


// --- Main Rule Handlers ---
const openAddMainModal = () => {
  mainModalMode.value = 'add';
  currentMainRule.value = {
    Name: '',
    Enabled: true,
    ListenIPv4: true,
    ListenIPv6: true,
    ListenAddr: '',
    ListenPort: 80,
    AccessControl: { Mode: 'disabled', ListName: '' },
    Security: { BlockOn404Count: 0, BlockOnBlockCount: 0 },
    TLS: { Enabled: false, MinVersion: 'TLS1.2', HTTP3Enabled: false, ECHEnabled: false },
    ApplyToSubRules: false,
    Limits: {
      RuleRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      ConnectionRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      IPRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      IPConnectionLimit: 0,
    },
    UnmatchedRequest: {
      Action: 'not_found',
      ProxyAddress: '',
      RedirectURL: '',
      StaticText: 'Not Found',
    },
    SubRules: []
  };
  isMainModalOpen.value = true;
};

const openEditMainModal = (rule) => {
  mainModalMode.value = 'edit';
  currentMainRule.value = JSON.parse(JSON.stringify(rule));
  originalMainRuleName.value = rule.Name;
  isMainModalOpen.value = true;
};

const handleMainSubmit = async () => {
  const url = mainModalMode.value === 'add' ? getApiUrl('/api/web-rules') : getApiUrl(`/api/web-rules/${originalMainRuleName.value}`);
  const method = mainModalMode.value === 'add' ? 'POST' : 'PUT';
  try {
    const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(currentMainRule.value) });
    if (response.ok) {
      isMainModalOpen.value = false;
      fetchWebRules();
    } else {
      const result = await response.json();
      alert(`操作失败: ${result.error}`);
    }
  } catch (error) { alert('请求失败'); }
};

const deleteMainRule = async (ruleName) => {
  if (!confirm(`确定要删除Web服务规则 "${ruleName}" 及其所有子规则吗？`)) return;
  try {
    const response = await fetch(getApiUrl(`/api/web-rules/${ruleName}`), { method: 'DELETE' });
    if (response.ok) fetchWebRules();
    else { const result = await response.json(); alert(`删除失败: ${result.error}`); }
  } catch (error) { alert('删除请求失败'); }
};

const toggleMainRule = async (rule) => {
  try {
    const response = await fetch(getApiUrl(`/api/web-rules/${rule.Name}/toggle`), { method: 'POST' });
    const result = await response.json();
    if (response.ok) {
        rule.Enabled = result.enabled;
        fetchRuleStatuses();
    }
    else alert(`切换失败: ${result.error}`);
  } catch (error) { alert('请求失败'); }
};

// --- Sub Rule Handlers ---
const openAddSubModal = (mainRule) => {
  subModalMode.value = 'add';
  currentMainRule.value = mainRule;
  currentSubRule.value = {
    Name: '', Enabled: true, ServiceType: 'reverse_proxy',
    FrontendAddress: '',
    Backend: { Address: '', IgnoreTLSCert: false, UseTargetHostHeader: false, GrpcSecure: false, DisableKeepAlives: false },
    RedirectURL: '', CorazaWAF: '无',
    Security: { BlockOn404Count: 0, BlockOnCorazaCount: 0 },
    Network: { DisableConnectionReuse: false, NetworkType: 'tcp', HttpClientTimeoutSec: 30 },
    ClientIP: { FromHeader: false, FromHeaderName: 'X-Forwarded-For', AddToHeader: false, AddToHeaderName: 'X-Forwarded-For', AddProtoToHeader: false, AddProtoToHeaderName: 'X-Forwarded-Proto', AddHostToHeader: false, AddHostToHeaderName: 'X-Forwarded-Host' },
    ForwardedHeaders: { Enabled: true },
    CORSEnabled: false,
    Auth: { Enabled: false, Username: '', Password: '' },
    IPFilter: { Mode: 'disabled', ListName: '' },
    UserAgentFilter: { Mode: 'disabled', List: [] },
    CustomRobotTxt: '',
    ForceHTTPS: false,
    Limits: {
      RuleRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      ConnectionRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      IPRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      IPConnectionLimit: 0,
    },
  };
  isSubModalOpen.value = true;
};

const openEditSubModal = (mainRule, subRule) => {
    subModalMode.value = 'edit';
    currentMainRule.value = mainRule;
    currentSubRule.value = {
        ForwardedHeaders: { Enabled: true }, 
        ...JSON.parse(JSON.stringify(subRule))
    };
    originalSubRuleName.value = subRule.Name;
    isSubModalOpen.value = true;
};

const handleSubSubmit = async () => {
  const url = subModalMode.value === 'add' ?
    getApiUrl(`/api/web-rules/${currentMainRule.value.Name}/sub-rules`) :
    getApiUrl(`/api/web-rules/${currentMainRule.value.Name}/sub-rules/${originalSubRuleName.value}`);
  const method = subModalMode.value === 'add' ? 'POST' : 'PUT';

  try {
    const response = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(currentSubRule.value) });
    if (response.ok) {
      isSubModalOpen.value = false;
      fetchWebRules();
    } else {
      const result = await response.json();
      alert(`操作失败: ${result.error}`);
    }
  } catch (error) { alert('请求失败'); }
};

const deleteSubRule = async (mainRuleName, subRuleName) => {
    if (!confirm(`确定要删除子规则 "${subRuleName}" 吗？`)) return;
    try {
        const response = await fetch(getApiUrl(`/api/web-rules/${mainRuleName}/sub-rules/${subRuleName}`), { method: 'DELETE' });
        if(response.ok) fetchWebRules();
        else { const result = await response.json(); alert(`删除失败: ${result.error}`); }
    } catch(error) { alert('请求失败'); }
};

const toggleSubRule = async (mainRuleName, subRule) => {
    try {
        const url = getApiUrl(`/api/web-rules/${mainRuleName}/sub-rules/${subRule.Name}/toggle`);
        const response = await fetch(url, { method: 'POST' });
        const result = await response.json();
        if (response.ok) {
            subRule.Enabled = result.enabled;
        } else {
            alert(`切换失败: ${result.error}`);
        }
    } catch (error) {
        alert('请求失败');
    }
};

const handleGlobalClick = (event) => {
    if (isTooltipVisible.value && tooltipRef.value && !tooltipRef.value.contains(event.target)) {
        isTooltipVisible.value = false;
    }
};

watch(selectedCategory, () => {
    selectedIpList.value = '';
});

onMounted(() => {
  connectWebSocket();
  fetchWebRules();
  fetchIPLists();
  fetchWafRuleSets();
  window.addEventListener('mousedown', handleGlobalClick);
});

onUnmounted(() => {
  if (socket) socket.close();
  window.removeEventListener('mousedown', handleGlobalClick);
});
</script>

<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Web 服务规则 ({{ webRules.length }})</h2>
      <button @click="openAddMainModal" class="btn">+ 添加 Web 服务</button>
    </div>
    <div v-if="!webRules || webRules.length === 0" class="empty-state-small">暂无Web服务规则...</div>
    <div v-for="rule in webRules" :key="rule.Name" class="main-rule-container">
        <div class="main-rule-header" :class="{ 'disabled-rule': !ruleStatuses[rule.Name] || ruleStatuses[rule.Name] === 'stopped' }">
            <div class="main-rule-title">
                <input type="checkbox" :checked="rule.Enabled" @click.prevent="toggleMainRule(rule)" class="main-toggle">
                <h3>{{ rule.Name }}</h3>
                <span :class="['status-tag', ruleStatuses[rule.Name]]">
                  {{ ruleStatuses[rule.Name] === 'running' ? '运行中' : (ruleStatuses[rule.Name] === 'error' ? '错误' : '已停止') }}
                </span>
                <span class="listen-address-display">{{ getListenAddressDisplay(rule) }}</span>
            </div>
            <div class="main-rule-actions">
                <div class="status-item connections" @click="openConnectionsModal(rule.Name, null)">
                    <IconLink /><span>连接:</span> <span class="count">{{ connectionsCount[rule.Name] || 0 }}</span>
                </div>
                <div class="status-item logs" @mouseenter="showLogTooltip($event, rule.Name)" @mouseleave="hideLogTooltip" @click="openLogModal(rule.Name)">
                    <IconLogs /><span>日志</span>
                </div>
                <button @click="openAddSubModal(rule)" class="btn btn-secondary">添加子规则</button>
                <button @click="openEditMainModal(rule)" class="btn-icon" title="编辑主规则"><IconEdit/></button>
                <button @click="deleteMainRule(rule.Name)" class="btn-icon btn-danger" title="删除主规则"><IconDelete/></button>
            </div>
        </div>
        <div class="sub-rule-list">
            <div v-if="!rule.SubRules || rule.SubRules.length === 0" class="empty-state-small">暂无子规则...</div>
            <table v-else>
                <thead>
                    <tr>
                        <th>状态</th>
                        <th>子规则名称</th>
                        <th>前端地址/域名</th>
                        <th>服务类型</th>
                        <th>后端地址/重定向URL</th>
                        <th style="width: 200px;">实时状态</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for="subRule in rule.SubRules" :key="subRule.Name">
                        <td>
                          <div class="status-cell">
                            <label class="switch small-switch">
                              <input type="checkbox" :checked="subRule.Enabled" @click.prevent="toggleSubRule(rule.Name, subRule)">
                              <span class="slider round"></span>
                            </label>
                          </div>
                        </td>
                        <td>{{ subRule.Name }}</td>
                        <td>{{ subRule.FrontendAddress }}</td>
                        <td>{{ subRule.ServiceType === 'reverse_proxy' ? '反向代理' : '重定向' }}</td>
                        <td>{{ subRule.ServiceType === 'reverse_proxy' ? subRule.Backend.Address : subRule.RedirectURL }}</td>
                        <td>
                            <div class="sub-rule-status">
                                <div class="status-item connections" @click="openConnectionsModal(rule.Name, subRule.Name)">
                                    <IconLink /> <span class="count">{{ connectionsCount[`${rule.Name}-${subRule.Name}`] || 0 }}</span>
                                </div>
                                <div class="status-item logs" @mouseenter="showLogTooltip($event, `${rule.Name} ${subRule.Name}`)" @mouseleave="hideLogTooltip" @click="openLogModal(`${rule.Name} ${subRule.Name}`)">
                                    <IconLogs />
                                </div>
                            </div>
                        </td>
                        <td class="sub-rule-actions">
                            <button @click="openEditSubModal(rule, subRule)" class="btn-icon" title="编辑子规则"><IconEdit/></button>
                            <button @click="deleteSubRule(rule.Name, subRule.Name)" class="btn-icon btn-danger" title="删除子规则"><IconDelete/></button>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <div v-if="isMainModalOpen" class="modal-overlay" @click.self="isMainModalOpen = false">
      <div class="modal-content large">
         <h2>{{ mainModalMode === 'add' ? '添加新 Web 服务' : '编辑 Web 服务' }}</h2>
        <form @submit.prevent="handleMainSubmit">

          <div class="form-section">
            <h4>基础设置</h4>
            <div class="form-row">
                <div class="form-group"><label>规则名称</label><input v-model="currentMainRule.Name" type="text" required></div>
                <div class="form-group toggle-group"><label>启用规则</label><input type="checkbox" class="main-toggle" v-model="currentMainRule.Enabled"></div>
            </div>
            <div class="form-group">
                <label>监听类型</label>
                <div class="checkbox-group">
                    <label><input type="checkbox" v-model="currentMainRule.ListenIPv4"> IPv4</label>
                    <label><input type="checkbox" v-model="currentMainRule.ListenIPv6"> IPv6</label>
                </div>
            </div>
             <div class="form-row">
                <div class="form-group"><label>监听地址</label><input v-model="currentMainRule.ListenAddr" type="text" placeholder="留空监听所有地址"></div>
                <div class="form-group"><label>监听端口</label><input v-model.number="currentMainRule.ListenPort" type="number" required></div>
            </div>
          </div>

          <div class="form-section">
            <h4>IP 访问控制 (主规则)</h4>
            <div class="form-row">
                <div class="form-group">
                    <label>模式</label>
                    <select v-model="currentMainRule.AccessControl.Mode">
                        <option value="disabled">不启用</option>
                        <option value="whitelist">白名单</option>
                        <option value="blacklist">黑名单</option>
                    </select>
                </div>
                <div class="form-group" v-if="currentMainRule.AccessControl.Mode === 'whitelist'">
                    <label>选择IP名单 (白名单、IP集、国家IP)</label>
                    <select v-model="currentMainRule.AccessControl.ListName" required>
                      <option disabled value="">请选择一个IP名单</option>
                      <option v-for="list in availableWhitelists" :key="list.name" :value="list.name">
                        {{ list.name }} ({{ list.source }})
                      </option>
                    </select>
                </div>
                <div class="form-group" v-if="currentMainRule.AccessControl.Mode === 'blacklist'">
                    <label>选择IP名单 (黑名单、IP集、国家IP)</label>
                    <select v-model="currentMainRule.AccessControl.ListName" required>
                      <option disabled value="">请选择一个IP名单</option>
                      <option v-for="list in availableBlacklists" :key="list.name" :value="list.name">
                        {{ list.name }} ({{ list.source }})
                      </option>
                    </select>
                </div>

            </div>
          </div>
          <div class="form-section">
              <h4>速率与连接数限制 (主规则)</h4>
              <p class="description">主规则的限制会覆盖所有子规则的限制。0 表示不限制。</p>
              <div class="form-row">
                  <div class="form-group">
                      <label>单IP连接数</label>
                      <input type="number" v-model.number="currentMainRule.Limits.IPConnectionLimit">
                  </div>
              </div>
              <h5>主规则速率限制 (整个规则生效)</h5>
               <div class="form-row">
                  <div class="form-group">
                      <label>总上传速率 (KB/s)</label>
                      <input type="number" v-model.number="currentMainRule.Limits.RuleRateLimit.SendSpeedKBps">
                  </div>
                  <div class="form-group">
                      <label>总下载速率 (KB/s)</label>
                      <input type="number" v-model.number="currentMainRule.Limits.RuleRateLimit.ReceiveSpeedKBps">
                  </div>
              </div>
               <h5>单连接速率限制</h5>
               <div class="form-row">
                  <div class="form-group">
                      <label>单连接上传速率 (KB/s)</label>
                      <input type="number" v-model.number="currentMainRule.Limits.ConnectionRateLimit.SendSpeedKBps">
                  </div>
                  <div class="form-group">
                      <label>单连接下载速率 (KB/s)</label>
                      <input type="number" v-model.number="currentMainRule.Limits.ConnectionRateLimit.ReceiveSpeedKBps">
                  </div>
              </div>
              <h5>单IP速率限制</h5>
               <div class="form-row">
                  <div class="form-group">
                      <label>单IP上传速率 (KB/s)</label>
                      <input type="number" v-model.number="currentMainRule.Limits.IPRateLimit.SendSpeedKBps">
                  </div>
                  <div class="form-group">
                      <label>单IP下载速率 (KB/s)</label>
                      <input type="number" v-model.number="currentMainRule.Limits.IPRateLimit.ReceiveSpeedKBps">
                  </div>
              </div>
          </div>
           <div class="form-section">
                <h4>未匹配请求处理</h4>
                <p class="description">当请求的域名(Host)未匹配任何子规则时，执行以下操作。</p>
                <div class="form-group">
                    <label>操作类型</label>
                    <select v-model="currentMainRule.UnmatchedRequest.Action">
                        <option value="not_found">返回 404 Not Found (默认)</option>
                        <option value="close">关闭连接</option>
                        <option value="proxy">反向代理</option>
                        <option value="redirect">302重定向</option>
                        <option value="static_text">返回静态文本</option>
                    </select>
                </div>
                 <div class="form-group" v-if="currentMainRule.UnmatchedRequest.Action === 'proxy'">
                    <label>代理地址</label>
                    <input type="text" v-model="currentMainRule.UnmatchedRequest.ProxyAddress" placeholder="例如: http://127.0.0.1:8080">
                </div>
                <div class="form-group" v-if="currentMainRule.UnmatchedRequest.Action === 'redirect'">
                    <label>重定向 URL</label>
                    <input type="text" v-model="currentMainRule.UnmatchedRequest.RedirectURL" placeholder="例如: https://google.com">
                </div>
                <div class="form-group" v-if="currentMainRule.UnmatchedRequest.Action === 'static_text'">
                    <label>静态文本内容</label>
                    <textarea v-model="currentMainRule.UnmatchedRequest.StaticText" rows="3"></textarea>
                </div>
            </div>
          <div class="form-section">
            <h4>TLS / HTTPS 设置</h4>
            <div class="form-group toggle-group"><label>启用 TLS (HTTPS)</label><input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.Enabled"></div>
            <div v-if="currentMainRule.TLS.Enabled">
                <div class="form-group">
                    <label>TLS 最低版本</label>
                    <select v-model="currentMainRule.TLS.MinVersion">
                        <option value="TLS1.0">TLS 1.0</option>
                        <option value="TLS1.1">TLS 1.1</option>
                        <option value="TLS1.2">TLS 1.2</option>
                        <option value="TLS1.3">TLS 1.3</option>
                    </select>
                </div>
                <div class="form-group toggle-group">
                  <label>启用 HTTP/3</label>
                  <input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.HTTP3Enabled" :disabled="currentMainRule.TLS.MinVersion !== 'TLS1.3'">
                </div>
                <p class="description">需要 TLS v1.3。注意：HTTP/3 (QUIC/UDP) 流量的实时连接无法被追踪。</p>
                <div class="form-group toggle-group">
                  <label>启用 ECH (暂不支持)</label>
                  <input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.ECHEnabled" disabled>
                </div>
            </div>
          </div>
            <div class="form-actions">
                <button type="button" class="btn-cancel" @click="isMainModalOpen = false">取消</button>
                <button type="submit" class="btn-save">保存</button>
            </div>
        </form>
      </div>
    </div>

    <div v-if="isSubModalOpen" class="modal-overlay" @click.self="isSubModalOpen = false">
      <div class="modal-content extra-large">
        <h2>{{ subModalMode === 'add' ? '添加子规则' : '编辑子规则' }}</h2>
        <form @submit.prevent="handleSubSubmit">
            <div class="form-section">
                <h4>基础设置</h4>
                <div class="form-row">
                    <div class="form-group"><label>子规则名称</label><input type="text" v-model="currentSubRule.Name" required></div>
                    <div class="form-group toggle-group"><label>启用子规则</label><input type="checkbox" class="main-toggle" v-model="currentSubRule.Enabled"></div>
                </div>
                 <div class="form-group toggle-group">
                    <label>强制HTTPS (HTTP跳转到HTTPS)</label>
                    <input type="checkbox" class="main-toggle" v-model="currentSubRule.ForceHTTPS">
                </div>
            </div>
            <div class="form-section">
                <h4>服务类型</h4>
                 <div class="form-row">
                    <div class="form-group">
                        <label>服务类型</label>
                        <select v-model="currentSubRule.ServiceType">
                            <option value="reverse_proxy">反向代理</option>
                            <option value="redirect">重定向</option>
                        </select>
                    </div>
                    <div class="form-group"><label>前端地址 (域名/IP)</label><input type="text" v-model="currentSubRule.FrontendAddress" required></div>
                </div>
                <div v-if="currentSubRule.ServiceType === 'reverse_proxy'" class="form-group"><label>后端地址</label><input type="text" v-model="currentSubRule.Backend.Address" placeholder="例如 http://127.0.0.1:8080"></div>
                <div v-if="currentSubRule.ServiceType === 'redirect'" class="form-group"><label>重定向URL</label><input type="text" v-model="currentSubRule.RedirectURL"></div>
            </div>
            
            <div v-if="currentSubRule.ServiceType === 'reverse_proxy'" class="form-section">
                <h4>反向代理请求头</h4>
                 <div class="form-group toggle-group">
                    <label>自动添加常见反向代理请求头</label>
                    <input type="checkbox" class="main-toggle" v-model="currentSubRule.ForwardedHeaders.Enabled">
                </div>
                <p class="description">启用后，将自动添加 X-Real-IP, X-Forwarded-For, X-Forwarded-Proto, X-Real-Proto, X-Forwarded-Host, X-Forwarded-Port 等请求头。</p>
            </div>

            <div v-if="currentSubRule.ServiceType === 'reverse_proxy'" class="form-section">
                <h4>客户端IP与协议头</h4>
                <div class="form-group toggle-group">
                  <label>优先从Header头部获取客户端IP</label>
                  <input type="checkbox" class="main-toggle" v-model="currentSubRule.ClientIP.FromHeader">
                </div>
                 <div v-if="currentSubRule.ClientIP.FromHeader" class="form-group">
                  <label>Header名称</label>
                  <input type="text" v-model="currentSubRule.ClientIP.FromHeaderName">
                </div>
            </div>

            <div class="form-section">
                <h4>IP 访问控制 (子规则)</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label>模式</label>
                        <select v-model="currentSubRule.IPFilter.Mode">
                            <option value="disabled">不启用</option>
                            <option value="whitelist">白名单</option>
                            <option value="blacklist">黑名单</option>
                        </select>
                    </div>
                    <div class="form-group" v-if="currentSubRule.IPFilter.Mode === 'whitelist'">
                        <label>选择IP名单 (白名单、IP集、国家IP)</label>
                        <select v-model="currentSubRule.IPFilter.ListName" required>
                          <option disabled value="">请选择一个IP名单</option>
                          <option v-for="list in availableWhitelists" :key="list.name" :value="list.name">
                            {{ list.name }} ({{ list.source }})
                          </option>
                        </select>
                    </div>
                    <div class="form-group" v-if="currentSubRule.IPFilter.Mode === 'blacklist'">
                        <label>选择IP名单 (黑名单、IP集、国家IP)</label>
                        <select v-model="currentSubRule.IPFilter.ListName" required>
                          <option disabled value="">请选择一个IP名单</option>
                          <option v-for="list in availableBlacklists" :key="list.name" :value="list.name">
                            {{ list.name }} ({{ list.source }})
                          </option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="form-section">
                <h4>速率与连接数限制 (子规则)</h4>
                <p class="description">如果主规则设置了限制，则此处的限制无效。0 表示不限制。</p>
                <div class="form-row">
                    <div class="form-group">
                        <label>单IP连接数</label>
                        <input type="number" v-model.number="currentSubRule.Limits.IPConnectionLimit">
                    </div>
                </div>
                <h5>子规则速率限制 (整个子规则生效)</h5>
                <div class="form-row">
                    <div class="form-group">
                        <label>总上传速率 (KB/s)</label>
                        <input type="number" v-model.number="currentSubRule.Limits.RuleRateLimit.SendSpeedKBps">
                    </div>
                    <div class="form-group">
                        <label>总下载速率 (KB/s)</label>
                        <input type="number" v-model.number="currentSubRule.Limits.RuleRateLimit.ReceiveSpeedKBps">
                    </div>
                </div>
                <h5>单连接速率限制</h5>
                <div class="form-row">
                    <div class="form-group">
                        <label>单连接上传速率 (KB/s)</label>
                        <input type="number" v-model.number="currentSubRule.Limits.ConnectionRateLimit.SendSpeedKBps">
                    </div>
                    <div class="form-group">
                        <label>单连接下载速率 (KB/s)</label>
                        <input type="number" v-model.number="currentSubRule.Limits.ConnectionRateLimit.ReceiveSpeedKBps">
                    </div>
                </div>
                <h5>单IP速率限制</h5>
                <div class="form-row">
                    <div class="form-group">
                        <label>单IP上传速率 (KB/s)</label>
                        <input type="number" v-model.number="currentSubRule.Limits.IPRateLimit.SendSpeedKBps">
                    </div>
                    <div class="form-group">
                        <label>单IP下载速率 (KB/s)</label>
                        <input type="number" v-model.number="currentSubRule.Limits.IPRateLimit.ReceiveSpeedKBps">
                    </div>
                </div>
            </div>
            <div v-if="currentSubRule.ServiceType === 'reverse_proxy'" class="form-section">
                <h4>后端设置</h4>
                <div class="checkbox-group wrap">
                    <label><input type="checkbox" v-model="currentSubRule.Backend.IgnoreTLSCert"> 忽略后端TLS证书验证</label>
                    <label><input type="checkbox" v-model="currentSubRule.Backend.UseTargetHostHeader"> 使用目标地址Host请求头</label>
                    <label><input type="checkbox" v-model="currentSubRule.Backend.GrpcSecure"> grpc使用安全连接</label>
                    <label><input type="checkbox" v-model="currentSubRule.Network.DisableConnectionReuse"> 禁用连接复用</label>
                </div>
            </div>
             <div v-if="currentSubRule.ServiceType === 'reverse_proxy'" class="form-section">
                <h4>其他</h4>
                 <div class="form-group toggle-group">
                    <label>授权认证</label>
                    <input type="checkbox" class="main-toggle" v-model="currentSubRule.Auth.Enabled">
                </div>
                 <div v-if="currentSubRule.Auth.Enabled" class="form-row">
                    <div class="form-group">
                        <label>用户名</label>
                        <input type="text" v-model="currentSubRule.Auth.Username">
                    </div>
                    <div class="form-group">
                        <label>密码</label>
                        <input type="password" v-model="currentSubRule.Auth.Password">
                    </div>
                </div>
                <div class="form-group toggle-group">
                    <label>跨域支持 (CORS)</label>
                    <input type="checkbox" class="main-toggle" v-model="currentSubRule.CORSEnabled">
                </div>
            </div>
            <div class="form-section">
                <h4>安全与WAF</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label>Coraza WAF</label>
                        <select v-model="currentSubRule.CorazaWAF">
                            <option value="无">无</option>
                            <option v-for="rs in wafRuleSets" :key="rs.Name" :value="rs.Name">{{ rs.Name }}</option>
                        </select>
                    </div>
                    <div class="form-group"><label>单IP连续404限制</label><input type="number" v-model.number="currentSubRule.Security.BlockOn404Count"></div>
                    <div class="form-group"><label>单IP Coraza拦截限制</label><input type="number" v-model.number="currentSubRule.Security.BlockOnCorazaCount"></div>
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn-cancel" @click="isSubModalOpen = false">取消</button>
                <button type="submit" class="btn-save">保存子规则</button>
            </div>
        </form>
      </div>
    </div>

    <div v-if="isTooltipVisible" ref="tooltipRef" class="tooltip" :style="{ top: tooltipTop + 'px', left: tooltipLeft + 'px' }" @mouseenter="cancelTooltipHide" @mouseleave="hideLogTooltip">
        <pre>{{ tooltipContent.join('\n') }}</pre>
        <div class="tooltip-pagination">
            <div class="pagination-left">
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
            <a href="#" @click.prevent="handleViewDetailsClick(tooltipRuleName)" class="tooltip-details-link">查看详情</a>
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
    
    <div v-if="isConnModalOpen" class="modal-overlay" @click.self="isConnModalOpen = false">
      <div class="modal-content large">
        <h2>实时连接: {{ ruleForConnModal.sub ? `${ruleForConnModal.main} / ${ruleForConnModal.sub}` : ruleForConnModal.main }}</h2>
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
.panel { background-color: #f4f6f9; padding: 0; border: none; }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding: 1.5rem; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.btn { background-color: #007bff; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; font-size: 0.9rem; font-weight: 500; }
.btn-secondary { background-color: #6c757d; }
.main-rule-container { border: 1px solid #e0e0e0; border-radius: 8px; margin-bottom: 1.5rem; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.main-rule-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; background-color: #f8f9fa; border-bottom: 1px solid #e0e0e0; }
.main-rule-header.disabled-rule { background-color: #e9ecef; }
.main-rule-title { display: flex; align-items: center; gap: 1rem; }
.main-rule-title h3 { margin: 0; font-size: 1.2rem; }
.main-toggle { height: 22px; width: 22px; }
.main-rule-actions { display: flex; gap: 0.5rem; align-items: center; }
.status-item { display: flex; align-items: center; gap: 6px; padding: 0.5rem; border-radius: 5px; cursor: pointer; }
.status-item:hover { background-color: #e9ecef; }
.status-item .count { font-weight: bold; }
.btn-icon { background: none; border: none; cursor: pointer; padding: 0.5rem; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
.btn-icon:hover { background-color: #e0e0e0; }
.btn-icon.btn-danger { color: #dc3545; }
.sub-rule-list { padding: 1rem; }
.sub-rule-list table { width: 100%; border-collapse: collapse; }
.sub-rule-list th, .sub-rule-list td { padding: 0.8rem; text-align: left; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
.sub-rule-list th { font-weight: 600; font-size: 0.9rem; color: #6c757d; }
.sub-rule-list tr:last-child td { border-bottom: none; }
.status-dot { height: 10px; width: 10px; border-radius: 50%; display: inline-block; }
.status-dot.enabled { background-color: #28a745; }
.status-dot.disabled { background-color: #6c757d; }
.sub-rule-actions { display: flex; gap: 0.5rem; }
.sub-rule-status { display: flex; align-items: center; gap: 0.5rem; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6); display: flex; justify-content: center; align-items: flex-start; padding: 5vh 1rem; z-index: 1000; overflow-y: auto; box-sizing: border-box; }
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 100%; box-shadow: 0 5px 15px rgba(0,0,0,0.3); margin-bottom: 5vh; }
.modal-content.large { max-width: 800px; }
.modal-content.extra-large { max-width: 950px; }
.form-section { border-bottom: 1px solid #eee; padding-bottom: 1rem; margin-bottom: 1rem; }
.form-section:last-of-type { border-bottom: none; }
.form-section h4 { margin-top: 0; margin-bottom: 1rem; color: #333; }
.form-section h5 { margin-top: 1.5rem; margin-bottom: 1rem; font-size: 1rem; color: #555; border-bottom: 1px solid #eee; padding-bottom: 0.5rem;}
.form-group { margin-bottom: 1rem; }
.form-row { display: flex; gap: 1rem; }
.form-row .form-group { flex: 1; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.form-group input[type="text"], .form-group input[type="number"], .form-group input[type="password"], .form-group select, .form-group textarea { width: 100%; padding: 0.7rem; border: 1px solid #e0e0e0; border-radius: 5px; font-size: 1rem; box-sizing: border-box; }
.toggle-group { display: flex; align-items: center; justify-content: space-between; }
.checkbox-group { display: flex; gap: 1rem; align-items: center; }
.checkbox-group.wrap { flex-wrap: wrap; }
.checkbox-group label { display: flex; align-items: center; gap: 0.5rem; }
.description { font-size: 0.85rem; color: #6c757d; margin-top: -0.5rem; margin-bottom: 1rem; }
.form-actions { margin-top: 2rem; display: flex; justify-content: flex-end; gap: 1rem; }
.btn-cancel { background-color: #e0e0e0; color: #333; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.btn-save { background-color: #007bff; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.tooltip { position: fixed; background-color: rgba(40, 44, 52, 0.95); color: #dcdfe4; border: 1px solid #555; border-radius: 5px; padding: 0.75rem; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.75rem; z-index: 2000; max-width: 800px; }
.tooltip pre { margin: 0; max-height: 250px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
.tooltip-pagination { display: flex; justify-content: space-between; align-items: center; margin-top: 8px; gap: 5px; }
.tooltip-pagination .pagination-left { display: flex; align-items: center; gap: 5px; }
.tooltip-pagination button { background: #555; color: white; border: none; cursor: pointer; padding: 2px 6px; }
.tooltip-pagination button:disabled { background: #333; cursor: not-allowed; }
.tooltip-pagination select { background: #555; color: white; border: 1px solid #777; font-size: 0.7rem; }
.page-jump.small-jump input { width: 35px; text-align: center; font-size: 0.7rem; padding: 2px; }
.page-jump.small-jump { color: #ccc; }
.tooltip-details-link { color: #a7c5eb; text-decoration: none; cursor: pointer; }
.tooltip-details-link:hover { text-decoration: underline; }
.logs-container-modal { background-color: #282c34; color: #dcdfe4; border-radius: 5px; height: 50vh; overflow-y: auto; padding: 1rem; margin-bottom: 1rem; white-space: pre-wrap; word-break: break-all;}
.pagination-controls { display: flex; justify-content: center; align-items: center; gap: 10px; padding-top: 10px; }
.page-jump input { width: 50px; text-align: center; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; }
.status-tag { padding: 3px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 500; }
.status-tag.running { background-color: #d4edda; color: #155724; }
.status-tag.stopped { background-color: #e2e3e5; color: #383d41; }
.status-tag.error { background-color: #f8d7da; color: #721c24; }
.listen-address-display { font-family: monospace; background-color: #e9ecef; padding: 3px 8px; border-radius: 4px; font-size: 0.9rem; }
.status-cell { display: flex; align-items: center; gap: 8px; }

/* Styles for connection modal actions */
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
.switch { position: relative; display: inline-block; width: 40px; height: 22px; }
.switch.small-switch { width: 34px; height: 20px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; }
.slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .4s; }
.small-switch .slider:before { height: 14px; width: 14px; left: 3px; bottom: 3px; }
input:checked + .slider { background-color: #28a745; }
input:focus + .slider { box-shadow: 0 0 1px #28a745; }
input:checked + .slider:before { transform: translateX(18px); }
.small-switch input:checked + .slider:before { transform: translateX(14px); }
.slider.round { border-radius: 22px; }
.slider.round:before { border-radius: 50%; }
</style>