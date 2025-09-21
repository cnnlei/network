<script setup>
import { ref, onMounted } from 'vue';

const ipLists = ref({});
const ipListEditName = ref('');
const ipListEditText = ref('');

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const fetchIPLists = async () => {
  try {
    const response = await fetch(getApiUrl('/api/ip-lists'));
    if (response.ok) {
      ipLists.value = await response.json() || {};
    }
  } catch (error) { console.error('加载IP名单失败:', error); }
};

const saveIPLists = async () => {
  if (!confirm('确定要保存所有IP名单的修改吗？此操作会立即生效。')) return;
  try {
    const response = await fetch(getApiUrl('/api/ip-lists'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ipLists.value)
    });
    if (response.ok) {
      alert('IP名单已保存并热更新！');
      fetchIPLists();
    } else { 
      const errorData = await response.json();
      alert(`保存失败: ${errorData.error}`);
    }
  } catch (error) { alert('请求失败'); }
};

const editIPList = (name, ips) => {
  ipListEditName.value = name;
  ipListEditText.value = (ips || []).join('\n');
};

const updateIPListFromText = () => {
  if (ipListEditName.value && ipLists.value[ipListEditName.value] !== undefined) {
    ipLists.value[ipListEditName.value] = ipListEditText.value.split('\n').map(ip => ip.trim()).filter(ip => ip);
  }
};

const addNewIPList = () => {
  const newName = prompt('请输入新的IP名单名称:');
  // ** BUG FIX: 移除了对名称的正则校验，允许中文等任意字符 **
  if (newName && !ipLists.value[newName]) {
    ipLists.value[newName] = [];
    editIPList(newName, []);
  } else if (newName) {
    alert('名称无效或已存在！');
  }
};

const deleteIPList = (name) => {
  if (confirm(`确定要删除IP名单 "${name}" 吗？所有使用此名单的规则将不再受其保护！`)) {
    delete ipLists.value[name];
    if (ipListEditName.value === name) {
      ipListEditName.value = '';
      ipListEditText.value = '';
    }
  }
};

onMounted(() => {
  fetchIPLists(); 
});
</script>

<template>
  <div class="panel ip-list-panel">
    <div class="panel-header">
      <h2>IP名单管理</h2>
      <div>
        <button @click="addNewIPList" class="btn" style="margin-right: 10px;">+ 新建名单</button>
        <button @click="saveIPLists" class="btn btn-primary">保存所有IP名单</button>
      </div>
    </div>
    <div class="ip-list-manager">
      <div class="list-names">
        <div v-if="Object.keys(ipLists).length === 0" class="empty-state-small">暂无名单</div>
        <ul>
          <li v-for="(ips, name) in ipLists" :key="name" 
              :class="{ active: name === ipListEditName }"
              @click="editIPList(name, ips)">
            <span>{{ name }} ({{ ips ? ips.length : 0 }})</span>
            <button @click.stop="deleteIPList(name)" class="delete-list-btn" title="删除此名单">×</button>
          </li>
        </ul>
      </div>
      <div class="list-editor">
        <textarea v-if="ipListEditName" v-model="ipListEditText" @input="updateIPListFromText" rows="10" placeholder="每行一个IP或CIDR地址"></textarea>
        <div v-else class="empty-state-small">请选择或新建一个IP名单进行编辑。</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.panel-header h2 { margin-top: 0; font-size: 1.2rem; }
.btn { background-color: #007bff; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; font-size: 0.9rem; font-weight: 500; transition: background-color 0.2s; }
.btn:hover { background-color: #0056b3; }
.btn.btn-primary { background-color: #007bff; }
.ip-list-panel { border-left: 4px solid #ffc107; }
.ip-list-manager { display: flex; gap: 1.5rem; min-height: 400px; }
.list-names { flex-basis: 220px; flex-shrink: 0; border-right: 1px solid #e0e0e0; overflow-y: auto; padding-right: 1rem; }
.list-names ul { list-style-type: none; margin: 0; padding: 0; }
.list-names li { padding: 0.8rem; cursor: pointer; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; border: 1px solid transparent; }
.list-names li:hover { background-color: #f0f4ff; }
.list-names li.active { background-color: #007bff; color: white; border-color: #007bff; }
.delete-list-btn { background: none; border: none; color: inherit; font-size: 1.2rem; cursor: pointer; opacity: 0.5; }
.delete-list-btn:hover { opacity: 1; }
.list-editor { flex-grow: 1; display: flex; flex-direction: column; }
.list-editor textarea { width: 100%; height: 100%; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; resize: none; border: 1px solid #e0e0e0; border-radius: 5px; padding: 0.5rem; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; width: 100%; display: flex; align-items: center; justify-content: center; }
</style>