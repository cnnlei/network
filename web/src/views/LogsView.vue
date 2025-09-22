<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue';

const historicalLogs = ref([]);
const isLoadingLogs = ref(false);
const logTheme = ref('dark');
const rules = ref([]);
const selectedLogRule = ref('all');

// --- Pagination State ---
const currentPage = ref(1);
const pageSize = ref(50);
const totalPages = ref(1);
const totalLogs = ref(0);
const jumpToPage = ref(1);

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const fetchRules = async () => {
  try {
    const response = await fetch(getApiUrl('/api/rules'));
    if (response.ok) {
      rules.value = await response.json();
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
      jumpToPage.value = currentPage.value; // Sync input box with current page
      
    } else {
      const errorData = await response.json();
      historicalLogs.value = [`加载日志失败: ${errorData.error}`];
    }
  } catch (error) {
    console.error('加载历史日志失败:', error);
    historicalLogs.value = ['加载失败，无法连接到API。'];
  } finally {
    isLoadingLogs.value = false;
  }
};

const handleJumpToPage = () => {
    const page = parseInt(jumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= totalPages.value) {
        currentPage.value = page;
        fetchLogs();
    } else {
        alert(`请输入一个介于 1 和 ${totalPages.value} 之间的有效页码。`);
        jumpToPage.value = currentPage.value; // Reset to current page
    }
}

// Watch for filter changes to reset page number
watch([selectedLogRule, pageSize], () => {
  currentPage.value = 1;
  fetchLogs();
});

onMounted(() => {
  fetchRules();
  fetchLogs(); // Load initial logs on mount
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
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.panel-header h2 { margin: 0; font-size: 1.2rem; }
.log-controls { display: flex; align-items: center; gap: 1rem; }
.log-filter select { padding: 0.5rem; border-radius: 5px; border: 1px solid #e0e0e0; font-size: 0.9rem; }
.log-controls button.theme-toggle { background-color: #6c757d; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; }
.logs-container { border-radius: 5px; height: 65vh; overflow-y: auto; white-space: pre-wrap; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.85rem; padding: 1rem; margin-bottom: 1rem; }
.dark-theme { background-color: #282c34; color: #dcdfe4; }
.light-theme { background-color: #f9fafb; color: #333; border: 1px solid #e0e0e0; }

.pagination-controls-footer {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
    padding-top: 1rem;
    border-top: 1px solid #e0e0e0;
}
.pagination-controls-footer button, .pagination-controls-footer select {
    padding: 0.5rem 1rem;
    border-radius: 5px;
    border: 1px solid #ccc;
    background-color: #f8f9fa;
    cursor: pointer;
}
.pagination-controls-footer button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}
.page-jump {
    display: flex;
    align-items: center;
    gap: 5px;
}
.page-jump input {
    width: 50px;
    text-align: center;
    padding: 0.5rem;
    border-radius: 5px;
    border: 1px solid #ccc;
}
/* Hides the number input arrows in Chrome/Safari/Edge */
.page-jump input::-webkit-outer-spin-button,
.page-jump input::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
/* Hides the number input arrows in Firefox */
.page-jump input[type=number] {
  -moz-appearance: textfield;
}
</style>