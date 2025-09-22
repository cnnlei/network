<script setup>
import { ref, onMounted, watch } from 'vue';

const historicalLogs = ref([]);
const isLoadingLogs = ref(false);
const logTheme = ref('dark');
const rules = ref([]);
const selectedLogRule = ref('all');
const isSettingsModalOpen = ref(false);

const logSettings = ref({
  CleanupByTime: { Enabled: false, Mode: 'days', Value: 7 },
  CleanupByLines: { Enabled: false, RetainLines: 10000 },
  CleanupByRule: {},
});

const manualCleanup = ref({
  cleanupType: 'time', // 'time', 'total_lines', 'rule_lines', 'all'
  mode: 'days',
  value: 7,
  ruleName: '',
  retainLines: 1000,
});

const activeCleanupTab = ref('manual');

const currentPage = ref(1);
const pageSize = ref(50);
const totalPages = ref(1);
const totalLogs = ref(0);
const jumpToPage = ref(1);

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

// 新增：确保所有规则都有一个默认的清理设置
const ensureRuleSettings = () => {
    if (!rules.value || !logSettings.value.CleanupByRule) return;
    rules.value.forEach(rule => {
        if (!logSettings.value.CleanupByRule[rule.Name]) {
            logSettings.value.CleanupByRule[rule.Name] = { Enabled: false, RetainLines: 1000 };
        }
    });
};

const fetchRules = async () => {
  try {
    const response = await fetch(getApiUrl('/api/rules'));
    if (response.ok) {
        rules.value = await response.json() || [];
        if (rules.value.length > 0 && !manualCleanup.value.ruleName) {
            manualCleanup.value.ruleName = rules.value[0].Name;
        }
        ensureRuleSettings(); // 获取规则后，确保设置对象完整
    }
  } catch (error) { console.error('加载规则列表失败:', error); }
};

const fetchLogs = async () => {
  isLoadingLogs.value = true;
  historicalLogs.value = ['正在加载完整的日志...'];
  try {
    const ruleParam = selectedLogRule.value;
    const response = await fetch(getApiUrl(`/api/logs?rule=${ruleParam}&page=${currentPage.value}&pageSize=${pageSize.value}`));
    if (response.ok) {
      const data = await response.json();
      historicalLogs.value = data.logs.length > 0 ? data.logs : ['该规则下暂无日志记录。'];
      totalPages.value = data.totalPages;
      totalLogs.value = data.totalLogs;
      jumpToPage.value = currentPage.value;
    } else {
      historicalLogs.value = [`加载日志失败`];
    }
  } catch (error) {
    historicalLogs.value = ['加载失败，无法连接到API。'];
  } finally {
    isLoadingLogs.value = false;
  }
};

const fetchLogSettings = async () => {
    try {
        const response = await fetch(getApiUrl('/api/settings'));
        if(response.ok) {
            const data = await response.json();
            if (data && data.Log) {
                logSettings.value.CleanupByTime = Object.assign({ Enabled: false, Mode: 'days', Value: 7 }, data.Log.CleanupByTime);
                logSettings.value.CleanupByLines = Object.assign({ Enabled: false, RetainLines: 10000 }, data.Log.CleanupByLines);
                logSettings.value.CleanupByRule = data.Log.CleanupByRule || {};
                ensureRuleSettings(); // 获取设置后，再次确保对象完整
            }
        }
    } catch(e) { console.error("获取日志设置失败", e); }
};

const saveLogSettings = async () => {
    try {
        const response = await fetch(getApiUrl('/api/settings'));
        if (!response.ok) throw new Error("无法获取当前设置");
        const fullSettings = await response.json();
        
        fullSettings.Log = logSettings.value;

        const saveResponse = await fetch(getApiUrl('/api/settings'), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(fullSettings)
        });

        if (saveResponse.ok) {
            alert('自动清理设置已保存！');
            isSettingsModalOpen.value = false;
        } else {
            const errorData = await saveResponse.json();
            alert(`保存失败: ${errorData.error}`);
        }
    } catch (e) {
        alert(`请求失败: ${e.message}`);
    }
};

const executeManualCleanup = async () => {
    if (!confirm(`确定要执行日志清理吗？此操作不可逆！`)) return;
    
    try {
        const response = await fetch(getApiUrl('/api/logs/cleanup'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(manualCleanup.value)
        });
        const result = await response.json();
        alert(result.message || result.error);
        if(response.ok) {
            isSettingsModalOpen.value = false;
            fetchLogs();
        }
    } catch(e) {
        alert(`请求失败: ${e.message}`);
    }
}


const handleJumpToPage = () => {
    const page = parseInt(jumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= totalPages.value) {
        currentPage.value = page;
        fetchLogs();
    } else {
        alert(`请输入一个介于 1 和 ${totalPages.value} 之间的有效页码。`);
        jumpToPage.value = currentPage.value;
    }
}

watch([selectedLogRule, pageSize], () => {
  currentPage.value = 1;
  fetchLogs();
});

onMounted(() => {
  fetchLogs();
  fetchLogSettings();
  fetchRules();
});

</script>

<template>
  <div class="panel">
    <div class="panel-header">
       <h2>历史日志 (共 {{ totalLogs }} 条)</h2>
       <div class="log-controls">
         <div class="log-filter">
            <select id="rule-select" v-model="selectedLogRule">
              <option value="all">所有规则</option>
              <option v-for="rule in rules" :key="rule.Name" :value="rule.Name">{{ rule.Name }}</option>
            </select>
          </div>
          <button @click="isSettingsModalOpen = true" class="btn-secondary">日志设置与清理</button>
          <button @click="logTheme = logTheme === 'dark' ? 'light' : 'dark'" class="theme-toggle">
            切换到 {{ logTheme === 'dark' ? '亮色' : '暗色' }} 主题
          </button>
       </div>
    </div>
    
    <pre class="logs-container" :class="logTheme === 'dark' ? 'dark-theme' : 'light-theme'">{{ historicalLogs.join('\n') }}</pre>
    
    <div class="pagination-controls-footer">
        <select v-model="pageSize">
            <option :value="20">20 条/页</option>
            <option :value="50">50 条/页</option>
            <option :value="100">100 条/页</option>
            <option :value="200">200 条/页</option>
        </select>
        <button @click="currentPage > 1 && (currentPage--, fetchLogs())" :disabled="currentPage <= 1">上一页</button>
        <div class="page-jump">
            第
            <input type="number" v-model.number="jumpToPage" @keyup.enter="handleJumpToPage" min="1" :max="totalPages">
            / {{ totalPages }} 页
        </div>
        <button @click="currentPage < totalPages && (currentPage++, fetchLogs())" :disabled="currentPage >= totalPages">下一页</button>
    </div>
  </div>

  <div v-if="isSettingsModalOpen" class="modal-overlay" @click.self="isSettingsModalOpen = false">
      <div class="modal-content large">
          <h2>日志设置与清理</h2>
          
          <div class="tabs">
              <button :class="{ active: activeCleanupTab === 'manual' }" @click="activeCleanupTab = 'manual'">手动清理</button>
              <button :class="{ active: activeCleanupTab === 'auto' }" @click="activeCleanupTab = 'auto'">自动清理</button>
          </div>

          <div v-if="activeCleanupTab === 'manual'">
              <div class="form-group">
                <label>清理模式</label>
                <select v-model="manualCleanup.cleanupType">
                    <option value="time">按时间清理</option>
                    <option value="total_lines">按总条数保留</option>
                    <option value="rule_lines">按规则条数保留</option>
                    <option value="all">全部清理</option>
                </select>
              </div>

              <div v-if="manualCleanup.cleanupType === 'time'" class="form-group inline">
                <label>清理</label>
                <input type="number" v-model.number="manualCleanup.value">
                <select v-model="manualCleanup.mode">
                    <option value="minutes">分钟前</option>
                    <option value="hours">小时前</option>
                    <option value="days">天前</option>
                    <option value="months">月前</option>
                </select>
                <label>的日志</label>
              </div>

              <div v-if="manualCleanup.cleanupType === 'total_lines'" class="form-group inline">
                <label>保留最新的</label>
                <input type="number" v-model.number="manualCleanup.value">
                <label>条日志</label>
              </div>
              
              <div v-if="manualCleanup.cleanupType === 'rule_lines'" class="form-group inline">
                <label>对于规则</label>
                 <select v-model="manualCleanup.ruleName">
                    <option v-for="rule in rules" :key="rule.Name" :value="rule.Name">{{ rule.Name }}</option>
                 </select>
                <label>保留最新的</label>
                <input type="number" v-model.number="manualCleanup.retainLines">
                <label>条日志</label>
              </div>

              <div class="form-actions">
                  <button type="button" class="btn-danger" @click="executeManualCleanup">立即执行清理</button>
              </div>
          </div>
          
          <div v-if="activeCleanupTab === 'auto'">
              <div class="auto-cleanup-grid">
                <div class="form-section">
                    <h4>按时间</h4>
                    <div class="form-group toggle-group">
                        <label for="auto-cleanup-time-enabled">启用</label>
                        <input type="checkbox" id="auto-cleanup-time-enabled" v-model="logSettings.CleanupByTime.Enabled">
                    </div>
                    <div class="form-group inline" v-if="logSettings.CleanupByTime.Enabled">
                        <label>清理早于</label>
                        <input type="number" v-model.number="logSettings.CleanupByTime.Value">
                        <select v-model="logSettings.CleanupByTime.Mode">
                            <option value="minutes">分钟</option>
                            <option value="hours">小时</option>
                            <option value="days">天</option>
                            <option value="months">月</option>
                        </select>
                    </div>
                </div>

                <div class="form-section">
                    <h4>按总条数</h4>
                    <div class="form-group toggle-group">
                        <label for="auto-cleanup-lines-enabled">启用</label>
                        <input type="checkbox" id="auto-cleanup-lines-enabled" v-model="logSettings.CleanupByLines.Enabled">
                    </div>
                    <div class="form-group inline" v-if="logSettings.CleanupByLines.Enabled">
                        <label>保留最新的</label>
                        <input type="number" v-model.number="logSettings.CleanupByLines.RetainLines">
                        <label>条</label>
                    </div>
                </div>
              </div>

              <div class="form-section">
                <h4>按规则条数 (对每个规则独立生效)</h4>
                <div class="rule-cleanup-list">
                    <div v-for="rule in rules" :key="rule.Name" class="form-group inline rule-item">
                        <label class="rule-name">{{ rule.Name }}</label>
                        <input type="checkbox" v-model="logSettings.CleanupByRule[rule.Name].Enabled">
                        <label>启用，保留最新</label>
                        <input type="number" v-model.number="logSettings.CleanupByRule[rule.Name].RetainLines" :disabled="!logSettings.CleanupByRule[rule.Name].Enabled">
                        <label>条</label>
                    </div>
                </div>
              </div>

              <div class="form-actions">
                  <button type="button" class="btn-cancel" @click="isSettingsModalOpen = false">取消</button>
                  <button type="button" class="btn-save" @click="saveLogSettings">保存自动清理设置</button>
              </div>
          </div>

      </div>
  </div>
</template>

<style scoped>
/* (All styles remain the same as the previous version) */
.tabs { display: flex; border-bottom: 1px solid #e0e0e0; margin-bottom: 1.5rem; }
.tabs button { padding: 0.8rem 1.2rem; border: none; background-color: transparent; cursor: pointer; font-size: 1rem; position: relative; color: #6c757d; }
.tabs button.active { color: #007bff; font-weight: 600; }
.tabs button.active::after { content: ''; position: absolute; bottom: -1px; left: 0; width: 100%; height: 2px; background-color: #007bff; }
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.panel-header h2 { margin: 0; font-size: 1.2rem; }
.log-controls { display: flex; align-items: center; gap: 1rem; }
.log-filter select { padding: 0.5rem; border-radius: 5px; border: 1px solid #e0e0e0; font-size: 0.9rem; }
.log-controls button { padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; border: none; }
.theme-toggle { background-color: #6c757d; color: white; }
.btn-secondary { background-color: #5a6268; color: white; }
.btn-danger { background-color: #dc3545; color: white; }
.logs-container { border-radius: 5px; height: 65vh; overflow-y: auto; white-space: pre-wrap; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.85rem; padding: 1rem; margin-bottom: 1rem; }
.dark-theme { background-color: #282c34; color: #dcdfe4; }
.light-theme { background-color: #f9fafb; color: #333; border: 1px solid #e0e0e0; }
.pagination-controls-footer { display: flex; justify-content: center; align-items: center; gap: 10px; padding-top: 1rem; border-top: 1px solid #e0e0e0; }
.pagination-controls-footer button, .pagination-controls-footer select { padding: 0.5rem 1rem; border-radius: 5px; border: 1px solid #ccc; background-color: #f8f9fa; cursor: pointer; }
.pagination-controls-footer button:disabled { opacity: 0.6; cursor: not-allowed; }
.page-jump { display: flex; align-items: center; gap: 5px; }
.page-jump input { width: 50px; text-align: center; padding: 0.5rem; border-radius: 5px; border: 1px solid #ccc; }
.page-jump input::-webkit-outer-spin-button, .page-jump input::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.page-jump input[type=number] { -moz-appearance: textfield; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6); display: flex; justify-content: center; align-items: center; z-index: 1000; }
.modal-content { background-color: white; padding: 1.5rem 2rem; border-radius: 8px; width: 100%; max-width: 600px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
.modal-content.large { max-width: 700px; }
.modal-content h2 { margin-top: 0; }
.form-section { padding: 1rem 0; }
.form-section:not(:last-child) { border-bottom: 1px solid #eee; }
.form-section h4 { margin-top: 0; margin-bottom: 1rem; }
.form-group { margin-bottom: 1.5rem; }
.form-group.inline { display: flex; align-items: center; gap: 10px; }
.form-group.inline label { margin-bottom: 0; flex-shrink: 0; }
.form-group.inline input[type="number"] { width: 80px; }
.form-group.inline select { flex-grow: 1; }
.toggle-group { display: flex; align-items: center; justify-content: space-between; }
.form-group label { display: block; margin-bottom: 0.5rem; }
.form-group input, .form-group select { padding: 0.7rem; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
.form-actions { display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid #eee; }
.btn-save { background-color: #007bff; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.btn-cancel { background-color: #e0e0e0; color: #333; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.auto-cleanup-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
.rule-cleanup-list { max-height: 200px; overflow-y: auto; border: 1px solid #eee; padding: 1rem; border-radius: 5px; }
.rule-item { margin-bottom: 1rem; }
.rule-name { font-weight: 500; min-width: 120px; text-align: right; margin-right: 1rem; }
</style>