<script setup>
import { ref, onMounted, computed } from 'vue';

// Main data structure for all IP lists from the backend
const ipLists = ref({
  whitelists: {},
  blacklists: {},
  ip_sets: {},
  country_ip_lists: {},
});

// State for the UI
const activeTab = ref('whitelists');
const ipListEditName = ref('');
const ipListEditText = ref('');

// State for the "Add New List" modal
const isModalOpen = ref(false);
const newList = ref({
    name: '',
    type: 'manual', 
    source: 'CN'    
});
const isCreating = ref(false);

// List of countries for the dropdown
const countryList = ref({
    "CN": "中国", "US": "美国", "JP": "日本", "KR": "韩国", "GB": "英国", "DE": "德国", "FR": "法国", "RU": "俄罗斯", "CA": "加拿大", "AU": "澳大利亚", "IN": "印度", "BR": "巴西", "HK": "香港", "TW": "台湾"
});

// Computed property to get the lists for the currently active tab
const currentListObject = computed(() => {
  if (!activeTab.value || !ipLists.value) return {};
  return ipLists.value[activeTab.value] || {};
});

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

// Fetch all IP lists from the backend
const fetchIPLists = async () => {
  try {
    const response = await fetch(getApiUrl('/api/ip-lists'));
    if (response.ok) {
      const data = await response.json();
      ipLists.value = {
        whitelists: data.whitelists || {},
        blacklists: data.blacklists || {},
        ip_sets: data.ip_sets || {},
        country_ip_lists: data.country_ip_lists || {}
      };
    }
  } catch (error) { console.error('加载IP名单失败:', error); }
};

// Save all changes made in the UI back to the server
const saveIPLists = async () => {
  if (!confirm('确定要保存所有IP名单的修改吗？此操作会立即生效，并触发动态列表的更新。')) return;
  try {
    const response = await fetch(getApiUrl('/api/ip-lists'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ipLists.value)
    });
    if (response.ok) {
      alert('IP名单已保存！');
      fetchIPLists();
    } else { 
      const errorData = await response.json();
      alert(`保存失败: ${errorData.error}`);
    }
  } catch (error) { alert('请求失败'); }
};

// Switch between tabs (whitelists, blacklists, etc.)
const selectTab = (tabName) => {
  activeTab.value = tabName;
  ipListEditName.value = '';
  ipListEditText.value = '';
}

// Handle clicking on a list item to edit it
const editIPList = (name, list) => {
  ipListEditName.value = name;
  if (activeTab.value === 'country_ip_lists') {
      const listConfig = list;
      let typeText = listConfig.Type === 'country' ? '国家' : 'URL';
      let sourceText = listConfig.Type === 'country' ? (countryList.value[listConfig.Source] || listConfig.Source) : listConfig.Source;
      
      ipListEditText.value = `# 这是一个由 [${typeText}] 自动管理的名单。\n# IP内容由后台自动更新，此处不可编辑。\n\n# 来源: ${sourceText}`;
  } else {
      ipListEditText.value = (list || []).join('\n');
  }
};

// Update the local data as the user types in the textarea
const updateIPListFromText = () => {
  if (ipListEditName.value && activeTab.value !== 'country_ip_lists') {
    const list = ipLists.value[activeTab.value];
    if (list && list[ipListEditName.value] !== undefined) {
      list[ipListEditName.value] = ipListEditText.value.split('\n').map(ip => ip.trim()).filter(ip => ip && !ip.startsWith('#'));
    }
  }
};

// Open the modal for creating a new list
const openAddModal = () => {
    if (activeTab.value === 'country_ip_lists') {
        newList.value = { name: '', type: 'country', source: 'CN' };
    } else {
        newList.value = { name: '' };
    }
    isModalOpen.value = true;
};

// Handle the creation of a new list from the modal
const handleCreateList = () => {
    if (!newList.value.name) {
        alert('名单名称不能为空！');
        return;
    }
    if (currentListObject.value[newList.value.name]) {
        alert('名单名称已存在！');
        return;
    }
    const name = newList.value.name;

    if (activeTab.value === 'country_ip_lists') {
        ipLists.value.country_ip_lists[name] = {
            Type: newList.value.type,
            Source: newList.value.source,
            UpdateInterval: 60, // A default value
        };
        // After creating a dynamic list, we don't know the IPs yet, so we show a placeholder.
        editIPList(name, ipLists.value.country_ip_lists[name]);
    } else {
        ipLists.value[activeTab.value][name] = [];
        editIPList(name, []);
    }
    isModalOpen.value = false;
};

// Delete a list from the current tab
const deleteIPList = (name) => {
  if (confirm(`确定要删除IP名单 "${name}" 吗？所有使用此名单的规则将不再受其保护！`)) {
    delete currentListObject.value[name];
    if (ipListEditName.value === name) {
      ipListEditName.value = '';
      ipListEditText.value = '';
    }
  }
};

// Manually trigger a refresh for a dynamic list
const refreshList = async (name) => {
    try {
        const response = await fetch(getApiUrl(`/api/ip-lists/${name}/refresh`), { method: 'POST' });
        const result = await response.json();
        alert(result.message || result.error);
    } catch (error) {
        alert('刷新请求失败');
    }
};

onMounted(fetchIPLists);
</script>

<template>
  <div class="panel ip-list-panel">
    <div class="panel-header">
      <h2>IP名单管理</h2>
      <div>
        <button @click="openAddModal" class="btn" style="margin-right: 10px;">+ 新建名单</button>
        <button @click="saveIPLists" class="btn btn-primary">保存所有更改</button>
      </div>
    </div>

    <div class="tabs">
      <button :class="{ active: activeTab === 'whitelists' }" @click="selectTab('whitelists')">IP白名单</button>
      <button :class="{ active: activeTab === 'blacklists' }" @click="selectTab('blacklists')">IP黑名单</button>
      <button :class="{ active: activeTab === 'ip_sets' }" @click="selectTab('ip_sets')">IP集</button>
      <button :class="{ active: activeTab === 'country_ip_lists' }" @click="selectTab('country_ip_lists')">国家IP</button>
    </div>

    <div class="ip-list-manager">
      <div class="list-names">
        <div v-if="Object.keys(currentListObject).length === 0" class="empty-state-small">此分类下暂无名单</div>
        <ul>
          <li v-for="(list, name) in currentListObject" :key="name" 
              :class="{ active: name === ipListEditName }"
              @click="editIPList(name, list)">
            <div class="list-item-main">
                <span class="list-name-text">{{ name }}</span>
                <span v-if="activeTab !== 'country_ip_lists'" class="list-name-detail">
                    共 {{ list ? list.length : 0 }} 条规则
                </span>
                <span v-else class="list-name-detail">
                    类型: {{ list.Type === 'country' ? (countryList[list.Source] || list.Source) : 'URL' }}
                </span>
            </div>
            <div class="list-item-actions">
              <button v-if="activeTab === 'country_ip_lists'" @click.stop="refreshList(name)" class="action-btn refresh-btn" title="刷新">刷新</button>
              <button @click.stop="deleteIPList(name)" class="action-btn delete-btn" title="删除">×</button>
            </div>
          </li>
        </ul>
      </div>
      <div class="list-editor">
        <textarea 
            v-if="ipListEditName" 
            v-model="ipListEditText" 
            @input="updateIPListFromText" 
            :disabled="activeTab === 'country_ip_lists'"
            rows="10" 
            placeholder="请选择一个名单..."></textarea>
        <div v-else class="empty-state-small">请选择或新建一个IP名单进行编辑。</div>
      </div>
    </div>
  </div>

  <div v-if="isModalOpen" class="modal-overlay" @click.self="isModalOpen = false">
      <div class="modal-content">
          <h2>新建名单到 "{{ activeTab }}"</h2>
          <form @submit.prevent="handleCreateList">
              <div class="form-group">
                  <label>名单名称</label>
                  <input type="text" v-model="newList.name" placeholder="例如: my-cn-ips">
              </div>
              
              <div v-if="activeTab === 'country_ip_lists'">
                <div class="form-group">
                    <label>类型</label>
                    <select v-model="newList.type">
                        <option value="country">按国家</option>
                        <option value="url">按网址</option>
                    </select>
                </div>
                 <div class="form-group" v-if="newList.type === 'country'">
                    <label>选择国家/地区</label>
                    <select v-model="newList.source">
                        <option v-for="(name, code) in countryList" :key="code" :value="code">{{ name }}</option>
                    </select>
                </div>
                <div class="form-group" v-if="newList.type === 'url'">
                    <label>URL地址</label>
                    <input v-model="newList.source" type="url" placeholder="http://.../my_ips.txt">
                </div>
              </div>

              <div class="form-actions">
                  <button type="button" class="btn-cancel" @click="isModalOpen = false">取消</button>
                  <button type="submit" class="btn-save" :disabled="isCreating">{{ isCreating ? '创建中...' : '创建' }}</button>
              </div>
          </form>
      </div>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.btn { background-color: #007bff; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; font-size: 0.9rem; font-weight: 500; transition: background-color 0.2s; }
.btn-primary { background-color: #28a745; }
.ip-list-panel { border-left: 4px solid #ffc107; }
.tabs { display: flex; border-bottom: 1px solid #e0e0e0; margin-bottom: 1.5rem; }
.tabs button { padding: 0.8rem 1.2rem; border: none; background-color: transparent; cursor: pointer; font-size: 1rem; position: relative; color: #6c757d; }
.tabs button.active { color: #007bff; font-weight: 600; }
.tabs button.active::after { content: ''; position: absolute; bottom: -1px; left: 0; width: 100%; height: 2px; background-color: #007bff; }
.ip-list-manager { display: flex; gap: 1.5rem; min-height: 400px; }
.list-names { flex-basis: 250px; flex-shrink: 0; border-right: 1px solid #e0e0e0; overflow-y: auto; padding-right: 1rem; }
.list-names ul { list-style-type: none; margin: 0; padding: 0; }
.list-names li { padding: 0.8rem; cursor: pointer; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; border: 1px solid transparent; }
.list-names li:hover { background-color: #f0f4ff; }
.list-names li.active { background-color: #007bff; color: white; border-color: #007bff; }

.list-item-main {
    display: flex;
    flex-direction: column;
    overflow: hidden;
    gap: 2px;
}

.list-name-text {
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.list-name-detail {
    font-size: 0.75rem;
    color: #6c757d;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.list-names li.active .list-name-detail {
    color: #e0e0e0;
}

.list-item-actions { display: flex; align-items: center; gap: 5px; opacity: 0; transition: opacity 0.2s; padding-left: 10px; }
.list-names li:hover .list-item-actions { opacity: 1; }
.action-btn { background: none; border: none; color: inherit; font-size: 0.8rem; cursor: pointer; opacity: 0.6; padding: 4px 8px; border-radius: 4px; line-height: 1; }
.action-btn:hover { opacity: 1; background-color: rgba(0, 0, 0, 0.1); }
.delete-list-btn { font-size: 1.2rem; }

.list-editor { flex-grow: 1; display: flex; flex-direction: column; }
.list-editor textarea { width: 100%; height: 100%; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; resize: none; border: 1px solid #e0e0e0; border-radius: 5px; padding: 0.5rem; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; width: 100%; display: flex; align-items: center; justify-content: center; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6); display: flex; justify-content: center; align-items: center; z-index: 1000; }
.modal-content { background-color: white; padding: 2rem; border-radius: 8px; width: 100%; max-width: 400px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
.modal-content h2 { margin-top: 0; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: 0.5rem; }
.form-group input, .form-group select { width: 100%; padding: 0.7rem; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
.radio-group { display: flex; gap: 1rem; align-items: center; }
.form-actions { display: flex; justify-content: flex-end; gap: 1rem; margin-top: 1.5rem; }
.btn-save { background-color: #007bff; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.btn-cancel { background-color: #e0e0e0; color: #333; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
</style>