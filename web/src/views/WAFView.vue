<template>
  <div class="panel waf-panel">
    <div class="panel-header">
      <h2>Coraza WAF 管理</h2>
      <div class="header-actions">
        <div class="waf-toggle" v-show="activeTab === 'simple-rules' || activeTab === 'rulesets'">
          <span>全局 WAF 开关</span>
          <label class="switch">
            <input type="checkbox" :checked="isWafEnabled" @change="toggleWafStatus">
            <span class="slider round"></span>
          </label>
        </div>
        <div class="default-action-settings" v-show="activeTab === 'rulesets'">
          <label>默认动作</label>
          <div class="action-display">
            <span>{{ wafSettings.DefaultAction || '未设置' }}</span>
            <button @click="openModal('action')" class="icon-button">
              <IconEdit />
            </button>
          </div>
        </div>
        <button v-show="activeTab === 'rulesets'" @click="openModal('addRuleset')" class="btn btn-primary">+ 新建高级规则集</button>
        <button v-show="activeTab === 'simple-rules'" @click="openModal('addSimpleRule')" class="btn btn-primary">+ 新建简易规则</button>
      </div>
    </div>
    <div class="tabs">
      <button :class="{ active: activeTab === 'simple-rules' }" @click="activeTab = 'simple-rules'">简易规则管理</button>
      <button :class="{ active: activeTab === 'rulesets' }" @click="activeTab = 'rulesets'">高级规则集管理</button>
      <button :class="{ active: activeTab === 'logs' }" @click="activeTab = 'logs'">WAF 日志</button>
      <button :class="{ active: activeTab === 'dynamic' }" @click="activeTab = 'dynamic'">动态WAF 检测</button>
    </div>

    <div v-if="activeTab === 'simple-rules'">
        <div class="empty-state-small" v-if="simpleRuleSets.length === 0">
            <p>暂无简易规则。</p>
            <p class="small-text">通过向导创建的规则会显示在这里。</p>
        </div>
        <table v-else class="ruleset-table">
            <thead>
                <tr>
                    <th>名称</th>
                    <th>规则类型</th>
                    <th>规则详情</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="rs in simpleRuleSets" :key="rs.Name">
                    <td>{{ rs.DisplayName }}</td>
                    <td>{{ rs.SimpleType }}</td>
                    <td class="rules-column"><pre>{{ rs.Rules.join('\n') }}</pre></td>
                    <td class="actions-cell">
                       <button @click="openModal('editSimpleRule', rs)" class="btn-action">编辑</button>
                       <button @click="deleteRuleSet(rs.Name)" class="btn-action-danger">删除</button>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <div v-if="activeTab === 'rulesets'">
        <div v-if="advancedRuleSets.length === 0" class="empty-state-small">暂无高级 WAF 规则集...</div>
        <table v-else class="ruleset-table collapsible">
          <thead>
            <tr>
              <th style="width: 40px;"></th>
              <th>名称</th>
              <th>来源</th>
              <th>路径/URL</th>
              <th>规则数</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody v-for="rs in advancedRuleSets" :key="rs.Name">
            <tr class="main-row">
              <td>
                <button @click="toggleAdvancedRule(rs)" class="btn-expand">
                  {{ rs.isExpanded ? '[-]' : '[+]' }}
                </button>
              </td>
              <td>{{ rs.Name }}</td>
              <td>{{ rs.Source }}</td>
              <td>{{ rs.Path || 'N/A' }}</td>
              <td>{{ rs.Rules ? rs.Rules.length : '...' }}</td>
              <td class="actions-cell">
                <button @click="openModal('editRuleset', rs)" class="btn-action" :disabled="rs.Source!=='inline'">编辑</button>
                <button @click="deleteRuleSet(rs.Name)" class="btn-action-danger">删除</button>
              </td>
            </tr>
            <tr v-if="rs.isExpanded" class="details-row">
              <td colspan="6">
                <div class="rules-details">
                  <h4>规则内容:</h4>
                  <div v-if="rs.isLoading" class="loading-spinner">正在加载...</div>
                  <pre v-else-if="rs.Rules && rs.Rules.length > 0">{{ rs.Rules.join('\n') }}</pre>
                  <div v-else-if="rs.error" class="error-message">{{ rs.error }}</div>
                  <span v-else>此规则集没有定义任何内联规则。</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
    </div>


    <div v-if="activeTab === 'logs'">
        <div class="logs-container dark-theme">
            <div v-if="isLoadingLogs" class="empty-state-small">正在加载日志...</div>
            <div v-else-if="wafLogs.length === 0" class="empty-state-small">暂无 WAF 相关日志记录。</div>
            <div v-else v-for="(line, index) in wafLogs" :key="index" class="log-line">
                <span class="log-time">{{ parseAuditLog(line).timestamp }}</span>
                <span :class="['log-level', getLogLevelClass(parseAuditLog(line).level)]">{{ parseAuditLog(line).level }}</span>
                <span class="log-tag">{{ parseAuditLog(line).tag }}</span>
                <span class="log-message" :class="{ 'log-manager': parseAuditLog(line).message.includes('[WAFManager]') }">
    {{ parseAuditLog(line).message }}
</span>
            </div>
        </div>
        <div class="pagination-controls-footer">
            <select v-model="pageSize">
                <option :value="20">20 条/页</option>
                <option :value="50">50 条/页</option>
                <option :value="100">100 条/页</option>
                <option :value="200">200 条/页</option>
            </select>
            <button @click="currentPage > 1 && (currentPage--, fetchWafLogs())" :disabled="currentPage <= 1">上一页</button>
            <div class="page-jump">
                第
                <input type="number" v-model.number="jumpToPage" @keyup.enter="handleJumpToPage" min="1" :max="totalPages">
                / {{ totalPages }} 页
            </div>
            <button @click="currentPage < totalPages && (currentPage++, fetchWafLogs())" :disabled="currentPage >= totalPages">下一页</button>
        </div>
    </div>
    
    <div v-if="activeTab === 'dynamic'">
        <DynamicWAF />
    </div>
  </div>

  <div v-if="isModalOpen && (modalMode === 'addRuleset' || modalMode === 'editRuleset')" class="modal-overlay" @click.self="isModalOpen = false">
    <div class="modal-content large">
      <h2>{{ modalMode === 'addRuleset' ? '新建高级规则集' : '编辑高级规则集' }}</h2>
      <form @submit.prevent="handleRulesetSubmit">
        <div class="form-group">
          <label>规则集名称</label>
          <input type="text" v-model="currentRuleSet.Name" :disabled="modalMode === 'editRuleset'" required>
        </div>
        <div class="form-group">
          <label>规则来源</label>
          <select v-model="currentRuleSet.Source" :disabled="modalMode === 'editRuleset'">
            <option value="inline">手动输入</option>
            <option value="file">文件</option>
            <option value="url">URL</option>
          </select>
        </div>
        <div class="form-group" v-if="currentRuleSet.Source === 'file' || currentRuleSet.Source === 'url'">
          <label>{{ currentRuleSet.Source === 'file' ? '文件路径' : 'URL' }}</label>
          <input type="text" v-model="currentRuleSet.Path" required :disabled="modalMode === 'editRuleset'">
        </div>
        <div class="form-group" v-if="currentRuleSet.Source === 'inline'">
          <label>规则内容</label>
          <div v-for="(rule, index) in currentRuleSet.Rules" :key="index" class="rule-input-group">
            <textarea v-model="currentRuleSet.Rules[index]" rows="3"></textarea>
            <button type="button" @click="removeRule(index)" class="btn-remove-rule" v-if="currentRuleSet.Rules.length > 1">-</button>
          </div>
          <button type="button" @click="addRule" class="btn-add-rule">+ 添加规则</button>
        </div>
        <div class="form-actions">
          <button type="button" class="btn-cancel" @click="isModalOpen = false">取消</button>
          <button type="submit" class="btn-save">保存</button>
        </div>
      </form>
    </div>
  </div>
  
    <div v-if="isModalOpen && modalMode === 'action'" class="modal-overlay" @click.self="closeModal">
        <div class="modal-content">
          <h2>自定义规则默认动作</h2>
           <p>
            请分别配置默认动作的各个组成部分。
          </p>
          <div class="action-builder">
            <div class="form-group">
              <label for="action-phase">阶段 (Phase)</label>
              <select id="action-phase" v-model="actionParts.phase">
                <option value="1">1 (请求头阶段)</option>
                <option value="2">2 (请求体阶段)</option>
              </select>
              <small>推荐使用 `2`，可以覆盖 GET 和 POST 请求。</small>
            </div>

            <div class="form-group">
              <label for="action-main">动作 (Action)</label>
              <select id="action-main" v-model="actionParts.action">
                <option value="deny">拦截 (Deny)</option>
                <option value="pass">放行/审计 (Pass)</option>
              </select>
              <small>Deny 会阻止请求，Pass 仅记录日志。</small>
            </div>

            <div v-if="actionParts.action === 'deny'">
                <div class="form-group">
                  <label for="action-status">状态码 (Status)</label>
                  <input type="number" id="action-status" v-model.number="actionParts.status" placeholder="例如: 403" />
                  <small>拦截请求时返回给客户端的 HTTP 状态码。</small>
                </div>
                 <div class="form-group">
                  <label for="action-body">自定义提示内容 (Response Body)</label>
                  <textarea id="action-body" v-model="actionParts.customBody" rows="4" placeholder="例如: <h1>Access Denied</h1><p>Your request has been blocked.</p>"></textarea>
                  <small>留空则使用 WAF 默认页面。支持 HTML。</small>
                </div>
            </div>
            
            <div class="form-group-checkbox">
               <input type="checkbox" id="action-log" v-model="actionParts.log" />
               <label for="action-log">记录日志 (Log)</label>
               <small>强烈建议始终开启，用于审计和问题排查。</small>
            </div>
          </div>

          <div class="result-preview">
              <strong>动作字符串预览: </strong>
              <code>{{ generatedActionString }}</code>
          </div>

          <div class="form-actions">
            <button @click="closeModal" class="btn-cancel">取消</button>
            <button @click="saveDefaultAction" class="btn-save">应用设置</button>
          </div>
        </div>
      </div>
    
  <div v-if="isModalOpen && (modalMode === 'addSimpleRule' || modalMode === 'editSimpleRule')" class="modal-overlay" @click.self="isModalOpen = false">
    <div class="modal-content">
      <h2>{{ modalMode === 'addSimpleRule' ? '新建简易规则' : '编辑简易规则' }}</h2>
      <form @submit.prevent="handleSimpleRuleSubmit">
        <div class="form-group">
          <label>规则名称</label>
          <input type="text" v-model="simpleRule.name" required placeholder="例如: block-admin-access" :disabled="modalMode === 'editSimpleRule'">
          <small>为您的规则起一个便于识别的名称。</small>
        </div>
        <div class="form-group">
          <label>规则类型</label>
          <select v-model="simpleRule.type">
            <option value="directory">目录保护</option>
            <option value="file">文件保护</option>
            <option value="ratelimit">访问频率限制</option>
          </select>
        </div>

        <div class="form-group" v-if="simpleRule.type === 'directory' || simpleRule.type === 'file'">
          <label>路径 (支持 * 通配符)</label>
          <input type="text" v-model="simpleRule.path" required placeholder="/admin/* 或 *.php">
        </div>

        <div v-if="simpleRule.type === 'ratelimit'">
            <div class="form-group">
                <label>路径 (支持 * 通配符)</label>
                <input type="text" v-model="simpleRule.path" required placeholder="/api/login 或 *">
            </div>
            <div class="form-group">
                <label>时间窗口 (秒)</label>
                <input type="number" v-model.number="simpleRule.window" min="1" required>
                <small>在此时间段内统计请求次数。</small>
            </div>
            <div class="form-group">
                <label>请求数限制</label>
                <input type="number" v-model.number="simpleRule.limit" min="1" required>
                <small>在“时间窗口”内允许的最大请求次数。</small>
            </div>
            <div class="form-group">
                <label>封锁时间 (秒)</label>
                <input type="number" v-model.number="simpleRule.blockTime" min="1" required>
                <small>触发限制后，IP 被封锁的时长。</small>
            </div>
        </div>

        <div class="form-actions">
          <button type="button" class="btn-cancel" @click="isModalOpen = false">取消</button>
          <button type="submit" class="btn-save">保存规则</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed, watch } from 'vue';
import IconEdit from '../components/icons/IconEdit.vue';
import DynamicWAF from '../components/DynamicWAF.vue';

const SIMPLE_RULE_PREFIX = 'gf_simple_';

const wafRuleSets = ref([]);
const isModalOpen = ref(false);
const modalMode = ref('addSimpleRule');
const currentRuleSet = ref(null); 
const originalRuleSetName = ref('');
const isWafEnabled = ref(false);
const activeTab = ref('simple-rules');

const rulesetStates = reactive({});

const wafSettings = ref({ DefaultAction: '', Enabled: false, RuleSets: [], DefaultActionBody: '' });
const actionParts = reactive({
  phase: '2',
  action: 'deny',
  status: 403,
  log: true,
  customBody: '',
});

const simpleRule = reactive({
    name: '',
    type: 'directory',
    path: '',
    window: 60,
    limit: 10,
    blockTime: 300,
});

const wafLogs = ref([]);
const isLoadingLogs = ref(false);
const currentPage = ref(1);
const pageSize = ref(50);
const totalPages = ref(1);
const totalLogs = ref(0);
const jumpToPage = ref(1);

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const enhancedRuleSets = computed(() => {
    return wafRuleSets.value.map(rs => {
        if (!rulesetStates[rs.Name]) {
            rulesetStates[rs.Name] = { 
                isExpanded: false, 
                isLoading: false, 
                error: null,
                Rules: rs.Source === 'inline' ? rs.Rules : null 
            };
        }
        const state = rulesetStates[rs.Name];
        let isSimple = false, DisplayName = '', SimpleType = '';
        if (rs.Name.startsWith(SIMPLE_RULE_PREFIX) && rs.Rules && rs.Rules.length > 0) {
            const parsed = parseRuleString(rs.Rules.join('\n'));
            isSimple = true;
            DisplayName = rs.Name.substring(SIMPLE_RULE_PREFIX.length);
            SimpleType = parsed.type;
        }
        return {
            ...rs,
            isSimple,
            DisplayName,
            SimpleType,
            isExpanded: state.isExpanded,
            isLoading: state.isLoading,
            error: state.error,
            Rules: state.Rules || (rs.Source === 'inline' ? rs.Rules : null)
        };
    });
});

const simpleRuleSets = computed(() => enhancedRuleSets.value.filter(rs => rs.isSimple));
const advancedRuleSets = computed(() => enhancedRuleSets.value.filter(rs => !rs.isSimple));

const toggleAdvancedRule = async (ruleset) => {
  const state = rulesetStates[ruleset.Name];
  state.isExpanded = !state.isExpanded;
  if (state.isExpanded && ruleset.Source !== 'inline' && !state.Rules) {
    state.isLoading = true;
    state.error = null;
    try {
      const response = await fetch(getApiUrl(`/api/waf/rulesets/${ruleset.Name}/rules`));
      if (response.ok) {
        const rules = await response.json();
        state.Rules = rules && rules.length > 0 ? rules : ["(空规则列表)"];
      } else {
        state.error = `加载规则失败: ${await response.text()}`;
        state.Rules = null;
      }
    } catch (e) {
      state.error = `请求错误: ${e.message}`;
      state.Rules = null;
    } finally {
      state.isLoading = false;
    }
  }
};

const generatedActionString = computed(() => {
  let parts = [];
  if (actionParts.phase) parts.push(`phase:${actionParts.phase}`);
  if (actionParts.action) parts.push(actionParts.action);
  if (actionParts.action === 'deny' && actionParts.status) parts.push(`status:${actionParts.status}`);
  if (actionParts.log) parts.push('log');
  return parts.join(',');
});

const parseAuditLog = (line) => {
    try {
        const logData = JSON.parse(line);
        const transaction = logData.transaction;
        if (transaction && transaction.messages) {
            const reasons = transaction.messages.map(m => m.message).join(', ');
            return {
                timestamp: new Date(transaction.unix_timestamp * 1000).toLocaleString(),
                level: 'BLOCK',
                tag: '[WAF-AUDIT]',
                message: `BLOCK from ${transaction.client_ip} for ${transaction.request.host}${transaction.request.uri}. Reason: ${reasons}`,
            };
        }
    } catch (e) {}
    return { timestamp: '', level: 'RAW', tag: '', message: line };
};

const getLogLevelClass = (level) => {
    if (level === 'BLOCK') return 'log-block';
    return 'log-info';
};

const fetchWafStatus = async () => {
    try {
        const response = await fetch(getApiUrl('/api/waf/status'));
        if (response.ok) isWafEnabled.value = (await response.json()).enabled;
    } catch (error) { console.error('获取 WAF 状态失败:', error); }
};

const toggleWafStatus = async () => {
    try {
        const response = await fetch(getApiUrl('/api/waf/toggle'), { method: 'POST' });
        if (response.ok) isWafEnabled.value = (await response.json()).enabled;
    } catch (error) { console.error('切换 WAF 状态失败:', error); }
};

const fetchWafRuleSets = async () => {
  try {
    const response = await fetch(getApiUrl('/api/waf/rulesets'));
    if (response.ok) {
        wafRuleSets.value = await response.json() || [];
        const currentNames = new Set(wafRuleSets.value.map(rs => rs.Name));
        for (const name in rulesetStates) {
            if (!currentNames.has(name)) {
                delete rulesetStates[name];
            }
        }
    }
  } catch (error) { console.error('加载 WAF 规则集失败:', error); }
};

const fetchWafLogs = async () => {
  isLoadingLogs.value = true;
  wafLogs.value = [];
  try {
    const response = await fetch(getApiUrl(`/api/logs/waf?page=${currentPage.value}&pageSize=${pageSize.value}`));
    if (response.ok) {
      const data = await response.json();
      wafLogs.value = data.logs || [];
      totalPages.value = data.totalPages;
      totalLogs.value = data.totalLogs;
      jumpToPage.value = currentPage.value;
    } else {
      wafLogs.value = [`加载日志失败: ${await response.text()}`];
    }
  } catch (error) {
    wafLogs.value = ['加载失败，无法连接到API。'];
  } finally {
    isLoadingLogs.value = false;
  }
};

watch(activeTab, (newTab) => { if (newTab === 'logs') fetchWafLogs(); });
watch(pageSize, () => {
    currentPage.value = 1;
    if (activeTab.value === 'logs') fetchWafLogs();
});

const parseRuleString = (ruleStr) => {
    const result = { type: 'Unknown', path: '', window: 60, limit: 10, blockTime: 300 };
    if (!ruleStr) return result;
    if(ruleStr.includes("Simple Rule: Block directory")) {
        const match = ruleStr.match(/REQUEST_URI "@beginsWith ([^"]+)"/);
        if (match) {
            result.type = 'directory';
            result.path = match[1].endsWith('/') ? match[1] + '*' : match[1];
            return result;
        }
    }
    if(ruleStr.includes("Simple Rule: Block file")) {
        const match = ruleStr.match(/REQUEST_FILENAME "@rx ([^"]+)"/);
        if (match) {
            result.type = 'file';
            result.path = match[1].replace(/\\\//g, '/').replace(/\.\*/g, '*');
            return result;
        }
    }
    if(ruleStr.includes("Simple Rule: Rate limit of")) {
        const pathRegexMatch = ruleStr.match(/SecRule REQUEST_URI "@rx ([^"]+)"/);
        const windowExpireMatch = ruleStr.match(/expirevar:IP\.RATELIMIT_COUNT_\d+=(\d+)/);
        const limitGtMatch = ruleStr.match(/SecRule IP:RATELIMIT_COUNT_\d+ "@gt (\d+)"/);
        const blockTimeExpireMatch = ruleStr.match(/expirevar:IP\.BLOCKED_\d+=(\d+)/);
        if(pathRegexMatch && windowExpireMatch && limitGtMatch && blockTimeExpireMatch) {
            result.type = 'ratelimit';
            result.path = pathRegexMatch[1].replace(/\\\//g, '/').replace(/\.\*/g, '*');
            result.window = parseInt(windowExpireMatch[1], 10);
            result.limit = parseInt(limitGtMatch[1], 10);
            result.blockTime = parseInt(blockTimeExpireMatch[1], 10);
            return result;
        }
    }
    return result;
};

const openModal = (mode, item = null) => {
  modalMode.value = mode;
  if (mode === 'addSimpleRule') {
    Object.assign(simpleRule, { name: '', type: 'directory', path: '', window: 60, limit: 10, blockTime: 300 });
    isModalOpen.value = true;
  } else if (mode === 'editSimpleRule') {
    const parsed = parseRuleString(item.Rules.join('\n'));
    Object.assign(simpleRule, {
        name: item.DisplayName,
        type: parsed.type,
        path: parsed.path,
        window: parsed.window,
        limit: parsed.limit,
        blockTime: parsed.blockTime,
    });
    isModalOpen.value = true;
  } else if (mode === 'addRuleset') {
    currentRuleSet.value = { Name: '', Source: 'inline', Path: '', Rules: [''] };
    isModalOpen.value = true;
  } else if (mode === 'editRuleset') {
    originalRuleSetName.value = item.Name;
    const itemToEdit = JSON.parse(JSON.stringify(wafRuleSets.value.find(rs => rs.Name === item.Name)));
    if (!Array.isArray(itemToEdit.Rules)) itemToEdit.Rules = [''];
    currentRuleSet.value = itemToEdit;
    isModalOpen.value = true;
  } else if (mode === 'action') {
    parseActionString(wafSettings.value.DefaultAction, wafSettings.value.DefaultActionBody);
    isModalOpen.value = true;
  }
};

const closeModal = () => isModalOpen.value = false;

const handleSimpleRuleSubmit = async () => {
    if (!simpleRule.name) {
        alert('规则名称不能为空！');
        return;
    }
    let ruleString = '';
    const ruleIdBase = new Date().getTime() % 100000;
    const sanitizedPath = simpleRule.path.replace(/"/g, '\\"');
    const pathForRegex = sanitizedPath.replace(/\*/g, '.*').replace(/\//g, '\\/');
    if (simpleRule.type === 'directory') {
        const pathPrefix = sanitizedPath.endsWith('*') ? sanitizedPath.slice(0, -1) : sanitizedPath;
        ruleString = `SecRule REQUEST_URI "@beginsWith ${pathPrefix}" "id:${ruleIdBase + 1},phase:1,deny,status:403,log,msg:'Simple Rule: Block directory ${sanitizedPath}'"`;
    } else if (simpleRule.type === 'file') {
        ruleString = `SecRule REQUEST_FILENAME "@rx ${pathForRegex}" "id:${ruleIdBase + 2},phase:1,deny,status:403,log,msg:'Simple Rule: Block file ${sanitizedPath}'"`;
    } else if (simpleRule.type === 'ratelimit') {
        const blockTime = simpleRule.blockTime > 0 ? simpleRule.blockTime : 300;
        const unique_id = ruleIdBase;
        const rule0 = `SecAction "id:${ruleIdBase},phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"`;
        const sanitizedPath = simpleRule.path && simpleRule.path !== '*' ? simpleRule.path : '*';
        const pathForRegex = sanitizedPath === '*' ? '.*' :
            sanitizedPath
                .replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&')
                .replace(/\\\*/g, '.*');
        const rule1 = `SecRule IP:BLOCKED_${unique_id} "@eq 1" "id:${ruleIdBase + 1},phase:1,deny,status:403,log,msg:'IP %{REMOTE_ADDR} blocked for ${sanitizedPath}'"`;
        const rule2 = `SecRule REQUEST_URI "@rx ^${pathForRegex}$" "id:${ruleIdBase + 2},phase:2,nolog,pass,setvar:ip.ratelimit_count_${unique_id}=+1,expirevar:ip.ratelimit_count_${unique_id}=${simpleRule.window}"`;
        const rule3 = `SecRule IP:ratelimit_count_${unique_id} "@gt ${simpleRule.limit}" "id:${ruleIdBase + 3},phase:2,log,deny,status:429,setvar:IP.BLOCKED_${unique_id}=1,expirevar:IP.BLOCKED_${unique_id}=${blockTime},msg:'Rate limit of ${simpleRule.limit}/${simpleRule.window}s exceeded for ${sanitizedPath}, blocking IP %{REMOTE_ADDR} for ${blockTime}s.'"`;
        ruleString = `${rule0}\n${rule1}\n${rule2}\n${rule3}`;
    }
    const rulesetName = SIMPLE_RULE_PREFIX + simpleRule.name;
    const isUpdate = modalMode.value === 'editSimpleRule';
    const rulesetPayload = {
        Name: rulesetName, Source: 'inline', Path: '', Rules: ruleString.split('\n').filter(r => r)
    };
    const url = isUpdate ? getApiUrl(`/api/waf/rulesets/${rulesetName}`) : getApiUrl('/api/waf/rulesets');
    const method = isUpdate ? 'PUT' : 'POST';
    try {
        const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rulesetPayload) });
        if (response.ok) {
            isModalOpen.value = false;
            fetchWafRuleSets();
            alert('简易规则已保存并应用！');
        } else {
            const errorData = await response.json();
            alert(`操作失败: ${errorData.error || 'Unknown error'}`);
        }
    } catch (error) { alert('请求失败: ' + error.message); }
};

const handleRulesetSubmit = async () => {
  if (!currentRuleSet.value.Name || currentRuleSet.value.Name.startsWith(SIMPLE_RULE_PREFIX)) {
    alert(`规则集名称不能为空且不能以 "${SIMPLE_RULE_PREFIX}" 开头。`);
    return;
  }
  const url = modalMode.value === 'addRuleset' ? getApiUrl('/api/waf/rulesets') : getApiUrl(`/api/waf/rulesets/${originalRuleSetName.value}`);
  const method = modalMode.value === 'addRuleset' ? 'POST' : 'PUT';
  try {
    const response = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(currentRuleSet.value) });
    if (response.ok) {
      isModalOpen.value = false;
      await fetchWafRuleSets();
      activeTab.value = 'rulesets';
    } else {
        const errorData = await response.json();
        alert(`操作失败: ${errorData.error || 'Unknown error'}`);
    }
  } catch (error) { alert('请求失败: ' + error.message); }
};

const deleteRuleSet = async (ruleSetName) => {
  if (!confirm(`确定要删除 WAF 规则集 "${ruleSetName.replace(SIMPLE_RULE_PREFIX, '')}" 吗？`)) return;
  try {
    const response = await fetch(getApiUrl(`/api/waf/rulesets/${ruleSetName}`), { method: 'DELETE' });
    if (response.ok) {
      fetchWafRuleSets();
    } else {
        const errorData = await response.json();
        alert(`删除失败: ${errorData.error || 'Unknown error'}`);
    }
  } catch (error) { alert('删除请求失败: ' + error.message); }
};

const handleJumpToPage = () => {
    const page = parseInt(jumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= totalPages.value) {
        currentPage.value = page;
        fetchWafLogs();
    } else {
        alert(`请输入一个介于 1 和 ${totalPages.value} 之间的有效页码。`);
        jumpToPage.value = currentPage.value;
    }
};

const addRule = () => { if (currentRuleSet.value?.Rules) currentRuleSet.value.Rules.push(''); };
const removeRule = (index) => { if (currentRuleSet.value?.Rules?.length > 1) currentRuleSet.value.Rules.splice(index, 1); };

const fetchWafSettings = async () => {
    try {
        const response = await fetch(getApiUrl('/api/waf/config')); 
        if (response.ok) wafSettings.value = await response.json();
    } catch (error) { console.error('Failed to fetch WAF settings', error); }
};

const saveDefaultAction = async () => {
    const newWafConfig = { 
        ...wafSettings.value, 
        DefaultAction: generatedActionString.value,
        DefaultActionBody: actionParts.customBody,
    };
    try {
        const response = await fetch(getApiUrl('/api/waf/config'), { 
            method: 'PUT', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(newWafConfig) 
        });
        const result = await response.json();
        if (response.ok) {
            alert(result.message || '默认动作已保存并热重载！');
            wafSettings.value.DefaultAction = generatedActionString.value;
            wafSettings.value.DefaultActionBody = actionParts.customBody;
            closeModal();
        } else {
            alert(`保存失败: ${result.error}`);
        }
    } catch (error) { alert('请求失败: ' + error.message); }
};

const parseActionString = (str, body) => {
    const defaultParts = { phase: '2', action: 'pass', status: 403, log: false, customBody: '' };
    if (!str) {
        Object.assign(actionParts, defaultParts);
        return;
    }
    const parts = str.split(',');
    const parsed = {};
    parts.forEach(part => {
        const [key, value] = part.split(':');
        if (key === 'phase') parsed.phase = value;
        else if (key === 'status') parsed.status = parseInt(value, 10) || 403;
        else if (key === 'log') parsed.log = true;
        else if (['deny', 'pass', 'drop'].includes(key)) parsed.action = key;
    });
    
    parsed.customBody = body || '';
    Object.assign(actionParts, { ...defaultParts, ...parsed });
};

onMounted(() => {
    fetchWafRuleSets();
    fetchWafStatus();
    fetchWafSettings();
});
</script>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    min-height: 42px; /* Set a minimum height to prevent jiggle */
}
.header-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
}
.header-actions > * {
    visibility: visible;
    opacity: 1;
    transition: opacity 0.2s linear, visibility 0s;
}
.header-actions > *[style*="display: none;"] {
    visibility: hidden;
    opacity: 0;
    pointer-events: none;
}
.panel-header h2 { margin: 0; }
.waf-toggle { display: flex; align-items: center; gap: 0.5rem; }
.btn-primary { background-color: #007bff; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; }
.ruleset-table { width: 100%; border-collapse: collapse; }
.ruleset-table th, .ruleset-table td { padding: 0.8rem; text-align: left; border-bottom: 1px solid #e0e0e0; }
.ruleset-table.collapsible .main-row td { vertical-align: middle; }
.rules-column pre { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; color: #555; }
.rules-details { padding: 1rem; background-color: #f8f9fa; border-radius: 4px; margin: 0.5rem 0;}
.rules-details h4 { margin-top: 0; margin-bottom: 0.5rem; }
.rules-details pre { background-color: #fff; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; max-height: 300px; overflow-y: auto; }
.btn-expand { background: none; border: none; cursor: pointer; font-family: monospace; font-size: 1rem; padding: 0 0.5rem; }
.loading-spinner, .error-message { padding: 1rem; text-align: center; }
.error-message { color: #dc3545; background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; }
.btn-action:disabled { background-color: #e9ecef; color: #adb5bd; cursor: not-allowed; }
.actions-cell { display: flex; gap: 0.5rem; }
.btn-action, .btn-action-danger { padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; border: 1px solid transparent; }
.btn-action { background-color: #e9ecef; color: #495057; }
.btn-action-danger { background-color: #f8d7da; color: #721c24; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.6); display: flex; justify-content: center; align-items: center; z-index: 1000; }
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 90%; max-width: 500px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
.modal-content.large { max-width: 700px; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: 0.5rem; }
.form-group input, .form-group select, .form-group textarea { width: 100%; padding: 0.7rem; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
.form-group small { color: #888; font-size: 0.85rem; margin-top: 4px; display: block;}
.rule-input-group { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; }
.rule-input-group textarea { flex-grow: 1; }
.btn-remove-rule, .btn-add-rule { padding: 0.5rem; cursor: pointer; }
.form-actions { display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem; }
.btn-cancel, .btn-save { padding: 0.7rem 1.5rem; border-radius: 5px; border: none; }
.btn-cancel { background-color: #6c757d; color: white; }
.btn-save { background-color: #28a745; color: white; }
.switch { position: relative; display: inline-block; width: 50px; height: 28px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; }
.slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 4px; bottom: 4px; background-color: white; transition: .4s; }
input:checked + .slider { background-color: #28a745; }
input:focus + .slider { box-shadow: 0 0 1px #28a745; }
input:checked + .slider:before { transform: translateX(22px); }
.slider.round { border-radius: 28px; }
.slider.round:before { border-radius: 50%; }
.tabs { display: flex; border-bottom: 1px solid #e0e0e0; margin-bottom: 1.5rem; }
.tabs button { padding: 0.8rem 1.2rem; border: none; background-color: transparent; cursor: pointer; font-size: 1rem; position: relative; color: #6c757d; }
.tabs button.active { color: #007bff; font-weight: 600; }
.tabs button.active::after { content: ''; position: absolute; bottom: -1px; left: 0; width: 100%; height: 2px; background-color: #007bff; }
.empty-state-small { padding: 2rem; text-align: center; color: #6c757d; }
.empty-state-small .small-text { font-size: 0.9rem; color: #888; }
.logs-container { border-radius: 5px; height: 65vh; overflow-y: auto; white-space: pre-wrap; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.85rem; padding: 1rem; margin-bottom: 1rem; }
.dark-theme { background-color: #282c34; color: #dcdfe4; }
.pagination-controls-footer { display: flex; justify-content: center; align-items: center; gap: 10px; padding-top: 1rem; border-top: 1px solid #e0e0e0; }
.pagination-controls-footer button, .pagination-controls-footer select { padding: 0.5rem 1rem; border-radius: 5px; border: 1px solid #ccc; background-color: #f8f9fa; cursor: pointer; }
.pagination-controls-footer button:disabled { opacity: 0.6; cursor: not-allowed; }
.page-jump { display: flex; align-items: center; gap: 5px; }
.page-jump input { width: 50px; text-align: center; padding: 0.5rem; border-radius: 5px; border: 1px solid #ccc; }
.log-line { display: flex; flex-wrap: nowrap; gap: 1rem; align-items: baseline; }
.log-time { color: #999; flex-shrink: 0; }
.log-level { font-weight: bold; flex-shrink: 0; text-align: center; width: 50px; }
.log-level.log-info { color: #87cefa; }
.log-level.log-block { color: #ff6347; font-weight: bold; }
.log-tag { color: #add8e6; flex-shrink: 0; }
.log-message { flex-grow: 1; }
.default-action-settings { display: flex; flex-direction: column; gap: 0.25rem; }
.action-display { display: flex; align-items: center; gap: 0.5rem; background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 0.5rem 1rem; border-radius: 4px; }
.action-display span { font-family: monospace; }
.icon-button { background: none; border: none; cursor: pointer; padding: 0; color: #007bff; }
.action-builder { display: flex; flex-direction: column; gap: 1.5rem; margin-top: 1.5rem; }
.action-builder .form-group small { color: #888; font-size: 0.85rem; margin-top: 4px; }
.form-group-checkbox { display: flex; align-items: center; gap: 0.5rem; }
.form-group-checkbox label { font-weight: normal; }
.form-group-checkbox small { color: #888; margin-left: auto; }
.result-preview { margin-top: 2rem; padding: 1rem; background-color: #e9ecef; border-radius: 4px; border: 1px solid #dee2e6; }
.result-preview code { font-family: monospace; font-weight: bold; color: #0056b3; }
.log-message.log-manager { color: #ff6347; /* Tomato red, 和 BLOCK 级别一致 */ font-weight: bold; }
</style>