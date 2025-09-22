<script setup>
import { ref, onMounted, computed } from 'vue';

const globalAC = ref({
  Mode: 'priority',
  WhitelistEnabled: false,
  WhitelistListName: '',
  BlacklistEnabled: false,
  BlacklistListName: ''
});
const ipLists = ref({
  whitelists: {},
  blacklists: {},
  ip_sets: {},
  country_ip_lists: {},
  url_ip_sets: {},
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

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const fetchGlobalAC = async () => {
  try {
    const response = await fetch(getApiUrl('/api/global-acl'));
    if (response.ok) {
      const data = await response.json();
      globalAC.value = {
        Mode: data.Mode || 'priority',
        WhitelistEnabled: data.WhitelistEnabled || false,
        WhitelistListName: data.WhitelistListName || '',
        BlacklistEnabled: data.BlacklistEnabled || false,
        BlacklistListName: data.BlacklistListName || '',
      };
    }
  } catch (error) {
    console.error('加载全局访问控制配置失败:', error);
    alert('加载全局配置失败！');
  }
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
  } catch (error) {
    console.error('加载IP名单失败:', error);
  }
};

const saveGlobalAC = async () => {
  if (globalAC.value.WhitelistEnabled && !globalAC.value.WhitelistListName) {
    alert('启用全局白名单时，必须选择一个IP名单！');
    return;
  }
  if (globalAC.value.BlacklistEnabled && !globalAC.value.BlacklistListName) {
    alert('启用全局黑名单时，必须选择一个IP名单！');
    return;
  }
  
  if (!confirm('确定要保存全局访问控制设置吗？此操作会立即对所有新连接生效。')) {
    return;
  }
  
  try {
    const response = await fetch(getApiUrl('/api/global-acl'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(globalAC.value)
    });
    const result = await response.json();
    if (response.ok) {
      alert(result.message || '配置已保存并热更新！');
      fetchGlobalAC();
    } else {
      alert(`保存失败: ${result.error}`);
    }
  } catch (error) {
    alert('请求失败');
  }
};

onMounted(() => {
  fetchGlobalAC();
  fetchIPLists();
});
</script>

<template>
  <div>
    <div class="panel global-acl-panel">
      <div class="panel-header">
        <h2>全局访问控制</h2>
        <button @click="saveGlobalAC" class="btn btn-primary">保存设置</button>
      </div>
      
      <div class="form-container">
        <div class="form-group">
          <label for="mode-select">全局访问控制模式</label>
          <select id="mode-select" v-model="globalAC.Mode">
            <option value="priority">优先级模式 (白名单 > 黑名单 > 规则)</option>
            <option value="whitelist_only">仅白名单模式 (只允许白名单中的IP)</option>
            <option value="blacklist_only">仅黑名单模式 (只拒绝黑名单中的IP)</option>
          </select>
          <p class="description">选择应用于所有连接的全局安全策略。</p>
        </div>
      </div>
    </div>

    <div class="panel" v-if="globalAC.Mode === 'priority' || globalAC.Mode === 'whitelist_only'">
      <div class="panel-header">
        <h3>全局白名单</h3>
      </div>
      <div class="form-container">
        <div class="form-group toggle-group">
          <label for="whitelist-enabled-toggle">启用全局白名单</label>
          <label class="switch">
            <input type="checkbox" id="whitelist-enabled-toggle" v-model="globalAC.WhitelistEnabled">
            <span class="slider round"></span>
          </label>
        </div>

        <template v-if="globalAC.WhitelistEnabled">
          <div class="form-group">
            <label for="whitelist-list-select">选择IP名单 (白名单或IP集)</label>
            <select id="whitelist-list-select" v-model="globalAC.WhitelistListName" required>
              <option disabled value="">请选择一个IP名单</option>
              <option v-for="list in availableWhitelists" :key="list.name" :value="list.name">
                {{ list.name }} ({{ list.source }})
              </option>
            </select>
          </div>
        </template>
      </div>
    </div>

    <div class="panel" v-if="globalAC.Mode === 'priority' || globalAC.Mode === 'blacklist_only'">
      <div class="panel-header">
        <h3>全局黑名单</h3>
      </div>
      <div class="form-container">
        <div class="form-group toggle-group">
          <label for="blacklist-enabled-toggle">启用全局黑名单</label>
          <label class="switch">
            <input type="checkbox" id="blacklist-enabled-toggle" v-model="globalAC.BlacklistEnabled">
            <span class="slider round"></span>
          </label>
        </div>

        <template v-if="globalAC.BlacklistEnabled">
          <div class="form-group">
            <label for="blacklist-list-select">选择IP名单 (黑名单或IP集)</label>
            <select id="blacklist-list-select" v-model="globalAC.BlacklistListName" required>
              <option disabled value="">请选择一个IP名单</option>
              <option v-for="list in availableBlacklists" :key="list.name" :value="list.name">
                {{ list.name }} ({{ list.source }})
              </option>
            </select>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 2rem; }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid #e0e0e0;}
.panel-header h2 { margin: 0; font-size: 1.4rem; }
.panel-header h3 { margin: 0; font-size: 1.2rem; font-weight: 600; }
.btn { background-color: #007bff; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; cursor: pointer; font-size: 1rem; font-weight: 500; transition: background-color 0.2s; }
.btn:hover { background-color: #0056b3; }
.global-acl-panel { border-left: 4px solid #17a2b8; }
.global-acl-panel .panel-header { border-bottom: none; padding-bottom: 0; }
.form-container { max-width: 600px; }
.form-group { margin-bottom: 1.5rem; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; font-size: 1rem; }
.form-group select { width: 100%; padding: 0.7rem; border: 1px solid #e0e0e0; border-radius: 5px; font-size: 1rem; box-sizing: border-box; }
.toggle-group { display: flex; align-items: center; justify-content: space-between; }
.description { font-size: 0.9rem; color: #6c757d; margin-top: 0.75rem; }
.disabled-message { margin-top: 1rem; padding: 1rem; background-color: #f8f9fa; border-radius: 5px; color: #6c757d; }
.switch { position: relative; display: inline-block; width: 50px; height: 28px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; }
.slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 4px; bottom: 4px; background-color: white; transition: .4s; }
input:checked + .slider { background-color: #28a745; }
input:focus + .slider { box-shadow: 0 0 1px #28a745; }
input:checked + .slider:before { transform: translateX(22px); }
.slider.round { border-radius: 28px; }
.slider.round:before { border-radius: 50%; }
</style>