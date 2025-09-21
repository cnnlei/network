<script setup>
import { ref, onMounted, onUnmounted, computed, watch } from 'vue';

const historicalLogs = ref('等待实时事件...');
const isLoadingLogs = ref(false);
const logTheme = ref('dark');
const rules = ref([]); 
const selectedLogRule = ref('all');
let socket = null;

const reversedHistoricalLogs = computed(() => {
  if (!historicalLogs.value) return '日志内容为空或正在加载...';
  return historicalLogs.value.split('\n').reverse().join('\n');
});

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const connectWebSocket = () => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${wsProtocol}//${window.location.hostname}:8080/ws`);
  socket.onmessage = (event) => {
  try {
    const payload = JSON.parse(event.data);
    // 只有在 payload 中明确包含 recentLogs 字段时才更新
    if (payload.recentLogs !== undefined && payload.recentLogs !== null) {
      historicalLogs.value = payload.recentLogs || '暂无最新日志。';
    }
  } catch (e) { console.error("解析WebSocket数据失败:", e); }
};
  socket.onclose = () => setTimeout(connectWebSocket, 3000);
  socket.onerror = (error) => { console.error('WebSocket Error:', error); socket.close(); };
};

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
  historicalLogs.value = '正在加载完整的日志...';
  try {
    const ruleParam = selectedLogRule.value === 'all' ? '' : `?rule=${selectedLogRule.value}`;
    const response = await fetch(getApiUrl(`/api/logs${ruleParam}`));
    if (response.ok) {
      const logs = await response.text();
      historicalLogs.value = logs || '该规则下暂无日志记录。';
    } else {
      historicalLogs.value = `加载日志失败: ${response.statusText}`;
    }
  } catch (error) {
    console.error('加载历史日志失败:', error);
    historicalLogs.value = '加载失败，无法连接到API。';
  } finally {
    isLoadingLogs.value = false;
  }
};

onMounted(() => {
  connectWebSocket();
  fetchRules();
});

onUnmounted(() => {
  if (socket) socket.close();
});
</script>

<template>
  <div class="panel">
    <div class="log-controls">
      <div class="log-filter">
        <label for="rule-select">过滤完整日志:</label>
        <select id="rule-select" v-model="selectedLogRule" @change="fetchLogs">
          <option value="all">所有日志</option>
          <option v-for="rule in rules" :key="rule.Name" :value="rule.Name">{{ rule.Name }}</option>
        </select>
         <button @click="fetchLogs" :disabled="isLoadingLogs" style="margin-left: 10px;">
          {{ isLoadingLogs ? '加载中...' : '手动加载' }}
        </button>
      </div>
      <button @click="logTheme = logTheme === 'dark' ? 'light' : 'dark'" class="theme-toggle">
        切换到 {{ logTheme === 'dark' ? '亮色' : '暗色' }} 主题
      </button>
    </div>
     <div class="log-notice">
      <p>下方区域实时显示最新的50条日志。如需查看并过滤完整的历史日志，请使用上方的下拉框和加载按钮。</p>
    </div>
    <pre class="logs-container" :class="logTheme === 'dark' ? 'dark-theme' : 'light-theme'">{{ reversedHistoricalLogs }}</pre>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.log-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.log-filter { display: flex; align-items: center; }
.log-filter label { margin-right: 0.5rem; }
.log-filter select, .log-filter button { padding: 0.5rem; border-radius: 5px; border: 1px solid #e0e0e0; font-size: 0.9rem; }
.log-controls button.theme-toggle { background-color: #6c757d; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; }
.log-notice { font-size: 0.85rem; color: #6c757d; background-color: #f8f9fa; padding: 0.75rem 1rem; border-radius: 5px; margin-bottom: 1rem; border: 1px solid #dee2e6; }
.logs-container { border-radius: 5px; height: 60vh; overflow-y: auto; white-space: pre-wrap; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.85rem; padding: 1rem; }
.dark-theme { background-color: #282c34; color: #dcdfe4; }
.light-theme { background-color: #f9fafb; color: #333; border: 1px solid #e0e0e0; }
</style>