<script setup>
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue';
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

// --- Sub Rule State ---
const isSubModalOpen = ref(false);
const subModalMode = ref('add');
const currentSubRule = ref({});
const originalSubRuleName = ref('');

// --- IP Lists State ---
const ipLists = ref({ whitelists: {}, blacklists: {}, ip_sets: {}, country_ip_lists: {}, url_ip_sets: {} });

// --- Real-time Data State ---
const connections = ref([]);
const connectionsForModal = ref([]);
const isConnModalOpen = ref(false);
const ruleForConnModal = ref({});

const connectionsCount = computed(() => {
    const counts = {};
    if (webRules.value) {
        for (const rule of webRules.value) {
            counts[rule.Name] = connections.value.filter(c => c.rule === rule.Name && !c.sub_rule).length;
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


// --- Log Tooltip State ---
const tooltipRef = ref(null);
const isTooltipVisible = ref(false);
const tooltipContent = ref([]);
const tooltipTop = ref(0);
const tooltipLeft = ref(0);
let hideTooltipTimeout = null;

// --- Log Modal State ---
const isLogModalOpen = ref(false);
const logsForModal = ref([]);
const ruleForLogModal = ref('');
const isLoadingLogs = ref(false);
const logModalCurrentPage = ref(1);
const logModalPageSize = ref(50);
const logModalTotalPages = ref(1);
const logModalJumpToPage = ref(1);


const availableLists = computed(() => {
    const combined = { 
        ...ipLists.value.whitelists, 
        ...ipLists.value.blacklists,
        ...ipLists.value.ip_sets, 
        ...ipLists.value.country_ip_lists, 
        ...ipLists.value.url_ip_sets 
    };
    return Object.keys(combined);
});

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
const fetchWebRules = async () => {
    try {
        const response = await fetch(getApiUrl('/api/web-rules'));
        if (response.ok) webRules.value = await response.json() || [];
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
    isTooltipVisible.value = true;
    tooltipContent.value = ["加载中..."];

    await nextTick();
    const rect = event.currentTarget.getBoundingClientRect();
    if(tooltipRef.value) {
        const tooltipHeight = tooltipRef.value.offsetHeight;
        const tooltipWidth = tooltipRef.value.offsetWidth;

        let top = rect.bottom + 5;
        let left = rect.left;

        if (left + tooltipWidth > window.innerWidth) {
            left = window.innerWidth - tooltipWidth - 10;
        }
        if (top + tooltipHeight > window.innerHeight) {
            top = rect.top - tooltipHeight - 5;
        }
        
        tooltipTop.value = top;
        tooltipLeft.value = left;
    }

    try {
        const data = await fetchPaginatedLogs(ruleName, 1, 10);
        tooltipContent.value = data.logs.length > 0 ? data.logs : ['暂无日志记录'];
    } catch (e) {
        tooltipContent.value = ['日志加载失败'];
    }
};

const hideLogTooltip = () => {
    hideTooltipTimeout = setTimeout(() => { isTooltipVisible.value = false; }, 200);
};
const cancelTooltipHide = () => clearTimeout(hideTooltipTimeout);


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
    connectionsForModal.value = connections.value.filter(c => c.rule === main && c.sub_rule === sub);
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
    ListenPort: 80, // 默认HTTP端口
    AccessControl: { Mode: 'disabled', ListName: '' },
    Security: { BlockOn404Count: 0, BlockOnBlockCount: 0 },
    TLS: { Enabled: false, ForceHTTPS: false, MinVersion: 'TLS1.2', HTTP3Enabled: false, ECHEnabled: false },
    ApplyToSubRules: false,
    Limits: {
      RuleRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      ConnectionRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      IPRateLimit: { SendSpeedKBps: 0, ReceiveSpeedKBps: 0 },
      IPConnectionLimit: 0,
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
    if (response.ok) rule.Enabled = result.enabled;
    else alert(`切换失败: ${result.error}`);
  } catch (error) { alert('请求失败'); }
};

// --- Sub Rule Handlers ---
const openAddSubModal = (mainRule) => {
  subModalMode.value = 'add';
  currentMainRule.value = mainRule;
  currentSubRule.value = {
    Name: '', Enabled: true, OperationMode: 'simple', Tag: '', ServiceType: 'reverse_proxy',
    FrontendAddress: '', 
    Backend: { Address: '', IgnoreTLSCert: false, UseTargetHostHeader: false, GrpcSecure: false, DisableKeepAlives: false },
    RedirectURL: '', CorazaWAF: '无',
    Security: { BlockOn404Count: 0, BlockOnCorazaCount: 0 },
    Network: { DisableConnectionReuse: false, NetworkType: 'tcp', HttpClientTimeoutSec: 30 },
    ClientIP: { FromHeader: false, AddToHeader: false, AddToHeaderName: 'X-Forwarded-For', AddProtoToHeader: false, AddProtoToHeaderName: 'X-Forwarded-Proto' },
    CORSEnabled: false,
    Auth: { Enabled: false, Username: '', Password: '' },
    IPFilter: { Mode: 'disabled', ListName: '' },
    UserAgentFilter: { Mode: 'disabled', List: [] },
    CustomRobotTxt: '',
  };
  isSubModalOpen.value = true;
};

const openEditSubModal = (mainRule, subRule) => {
    subModalMode.value = 'edit';
    currentMainRule.value = mainRule;
    currentSubRule.value = JSON.parse(JSON.stringify(subRule));
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

onMounted(() => {
  connectWebSocket();
  fetchWebRules();
  fetchIPLists();
});

onUnmounted(() => {
  if (socket) socket.close();
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
        <div class="main-rule-header" :class="{ 'disabled-rule': !rule.Enabled }">
            <div class="main-rule-title">
                <input type="checkbox" :checked="rule.Enabled" @click.prevent="toggleMainRule(rule)" class="main-toggle">
                <h3>{{ rule.Name }}</h3>
                <span>{{ rule.ListenAddr || '*' }}:{{ rule.ListenPort }}</span>
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
                        <td><span :class="['status-dot', subRule.Enabled ? 'enabled' : 'disabled']"></span></td>
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
                <div class="form-group" v-if="currentMainRule.AccessControl.Mode !== 'disabled'">
                    <label>选择名单</label>
                    <select v-model="currentMainRule.AccessControl.ListName" required>
                        <option disabled value="">请选择IP名单</option>
                        <option v-for="name in availableLists" :key="name" :value="name">{{ name }}</option>
                    </select>
                </div>
            </div>
          </div>
          
          <div class="form-section">
            <h4>TLS / HTTPS 设置</h4>
            <div class="form-group toggle-group"><label>启用 TLS (HTTPS)</label><input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.Enabled"></div>
            <div v-if="currentMainRule.TLS.Enabled">
                <div class="form-group toggle-group"><label>强制HTTPS (HTTP跳转到HTTPS)</label><input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.ForceHTTPS"></div>
                <div class="form-group">
                    <label>TLS 最低版本</label>
                    <select v-model="currentMainRule.TLS.MinVersion">
                        <option value="TLS1.0">TLS 1.0</option>
                        <option value="TLS1.1">TLS 1.1</option>
                        <option value="TLS1.2">TLS 1.2</option>
                        <option value="TLS1.3">TLS 1.3</option>
                    </select>
                </div>
                <div class="form-group toggle-group"><label>禁用 HTTP/3</label><input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.HTTP3Enabled"></div>
                 <p class="description">盲目启用HTTP/3可能导致性能下降，且UDP访问请求暂不支持流量统计与连接管理功能。</p>
                <div class="form-group toggle-group"><label>禁用 ECH</label><input class="main-toggle" type="checkbox" v-model="currentMainRule.TLS.ECHEnabled"></div>
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
                <div class="form-row">
                    <div class="form-group"><label>操作模式</label><select v-model="currentSubRule.OperationMode"><option value="simple">简易模式</option><option value="custom">定制模式</option></select></div>
                    <div class="form-group"><label>标记</label><input type="text" v-model="currentSubRule.Tag"></div>
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
                <h4>后端设置</h4>
                <div class="checkbox-group wrap">
                    <label><input type="checkbox" v-model="currentSubRule.Backend.IgnoreTLSCert"> 忽略后端TLS证书验证</label>
                    <label><input type="checkbox" v-model="currentSubRule.Backend.UseTargetHostHeader"> 使用目标地址Host请求头</label>
                    <label><input type="checkbox" v-model="currentSubRule.Backend.GrpcSecure"> grpc使用安全连接</label>
                    <label><input type="checkbox" v-model="currentSubRule.Backend.DisableKeepAlives"> 禁用长连接</label>
                </div>
            </div>
            <div class="form-section">
                <h4>安全与WAF</h4>
                <div class="form-row">
                    <div class="form-group"><label>Coraza WAF</label><select v-model="currentSubRule.CorazaWAF"><option>无</option></select></div>
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
    </div>

    <div v-if="isLogModalOpen" class="modal-overlay" @click.self="isLogModalOpen = false">
      <div class="modal-content large">
        <h2>日志: {{ ruleForLogModal }}</h2>
        <pre v-if="isLoadingLogs" class="logs-container-modal">加载中...</pre>
        <pre v-else class="logs-container-modal">{{ logsForModal.join('\n') }}</pre>
        <div class="pagination-controls">
           <select v-model="logModalPageSize" @change="loadModalLogs">
                <option :value="50">50/页</option>
                <option :value="100">100/页</option>
                <option :value="200">200/页</option>
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
          <thead><tr><th>客户端地址</th><th>目标地址</th></tr></thead>
          <tbody>
            <tr v-for="conn in connectionsForModal" :key="conn.id">
              <td>{{ conn.clientAddr }}</td><td>{{ conn.targetAddr }}</td>
            </tr>
          </tbody>
        </table>
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
.sub-rule-list th, .sub-rule-list td { padding: 0.8rem; text-align: left; border-bottom: 1px solid #f0f0f0; }
.sub-rule-list th { font-weight: 600; font-size: 0.9rem; color: #6c757d; }
.sub-rule-list tr:last-child td { border-bottom: none; }
.status-dot { height: 10px; width: 10px; border-radius: 50%; display: inline-block; }
.status-dot.enabled { background-color: #28a745; }
.status-dot.disabled { background-color: #ced4da; }
.sub-rule-actions { display: flex; gap: 0.5rem; }
.sub-rule-status { display: flex; align-items: center; gap: 0.5rem; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6); display: flex; justify-content: center; align-items: flex-start; padding: 5vh 1rem; z-index: 1000; overflow-y: auto; box-sizing: border-box; }
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 100%; box-shadow: 0 5px 15px rgba(0,0,0,0.3); margin-bottom: 5vh; }
.modal-content.large { max-width: 800px; }
.modal-content.extra-large { max-width: 950px; }
.form-section { border-bottom: 1px solid #eee; padding-bottom: 1rem; margin-bottom: 1rem; }
.form-section:last-of-type { border-bottom: none; }
.form-section h4 { margin-top: 0; margin-bottom: 1rem; color: #333; }
.form-group { margin-bottom: 1rem; }
.form-row { display: flex; gap: 1rem; }
.form-row .form-group { flex: 1; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.form-group input[type="text"], .form-group input[type="number"], .form-group select { width: 100%; padding: 0.7rem; border: 1px solid #e0e0e0; border-radius: 5px; font-size: 1rem; box-sizing: border-box; }
.toggle-group { display: flex; align-items: center; justify-content: space-between; }
.checkbox-group { display: flex; gap: 1rem; align-items: center; }
.checkbox-group.wrap { flex-wrap: wrap; }
.checkbox-group label { display: flex; align-items: center; gap: 0.5rem; }
.description { font-size: 0.85rem; color: #6c757d; margin-top: 0.5rem; }
.form-actions { margin-top: 2rem; display: flex; justify-content: flex-end; gap: 1rem; }
.btn-cancel { background-color: #e0e0e0; color: #333; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.btn-save { background-color: #007bff; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.tooltip { position: fixed; background-color: rgba(40, 44, 52, 0.95); color: #dcdfe4; border: 1px solid #555; border-radius: 5px; padding: 0.75rem; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.75rem; white-space: pre; z-index: 2000; max-width: 800px; pointer-events: auto; }
.tooltip pre { margin: 0; max-height: 250px; overflow-y: auto; }
.logs-container-modal { background-color: #282c34; color: #dcdfe4; border-radius: 5px; height: 50vh; overflow-y: auto; padding: 1rem; margin-bottom: 1rem; }
.pagination-controls { display: flex; justify-content: center; align-items: center; gap: 10px; padding-top: 10px; }
.page-jump input { width: 50px; text-align: center; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; }
</style>