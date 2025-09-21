<script setup>
import { ref, defineProps, defineEmits, watch } from 'vue';

// --- Props and Emits ---
const props = defineProps({
  ipLists: Object
});
const emit = defineEmits(['save']);

// --- State ---
const internalIpLists = ref({});
const ipListEditName = ref('');
const ipListEditText = ref('');

// --- Watchers ---
watch(() => props.ipLists, (newVal) => {
  internalIpLists.value = JSON.parse(JSON.stringify(newVal || {}));
}, { immediate: true, deep: true });

// --- Methods ---
const editIPList = (name, ips) => {
  ipListEditName.value = name;
  ipListEditText.value = (ips || []).join('\n');
};

const updateIPListFromText = () => {
  if (ipListEditName.value && internalIpLists.value[ipListEditName.value] !== undefined) {
    internalIpLists.value[ipListEditName.value] = ipListEditText.value.split('\n').map(ip => ip.trim()).filter(ip => ip);
  }
};

const addNewIPList = () => {
  const newName = prompt('请输入新的IP名单名称 (只能用字母、数字、-):');
  const validNameRegex = /^[a-zA-Z0-9-]+$/;
  if (newName && validNameRegex.test(newName) && internalIpLists.value[newName] === undefined) {
    internalIpLists.value[newName] = [];
    editIPList(newName, []);
  } else if (newName) {
    alert('名称无效或已存在！');
  }
};

const deleteIPList = (name) => {
  if (confirm(`确定要删除IP名单 "${name}" 吗？所有使用此名单的规则将不再受其保护！`)) {
    delete internalIpLists.value[name];
    if (ipListEditName.value === name) {
      ipListEditName.value = '';
      ipListEditText.value = '';
    }
  }
};

const save = () => {
    emit('save', internalIpLists.value);
};

</script>

<template>
  <div class="panel ip-list-panel">
    <div class="panel-header">
      <h2>IP名单管理</h2>
      <div>
        <button @click="addNewIPList" class="add-rule-btn" style="margin-right: 10px;">+ 新建名单</button>
        <button @click="save" class="add-rule-btn">保存所有IP名单</button>
      </div>
    </div>
    <div class="ip-list-manager">
      <div class="list-names">
        <div v-if="Object.keys(internalIpLists).length === 0" class="empty-state-small">暂无名单</div>
        <ul>
          <li v-for="(ips, name) in internalIpLists" :key="name" 
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
/* 所有与IP名单管理相关的CSS都移到这里 */
.panel { background-color: var(--panel-bg); padding: 1.5rem; border-radius: 8px; box-shadow: var(--shadow); margin-bottom: 2rem;}
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.add-rule-btn { background-color: var(--primary-color); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 5px; cursor: pointer; font-size: 0.9rem; transition: background-color 0.2s; }
.add-rule-btn:hover { background-color: #0056b3; }
.ip-list-panel { border-left: 4px solid #ffc107; }
.ip-list-panel h2 { margin-top: 0; font-size: 1.2rem; }
.ip-list-manager { display: flex; gap: 1.5rem; min-height: 200px; max-height: 300px; }
.list-names { flex-basis: 220px; flex-shrink: 0; border-right: 1px solid var(--border-color); overflow-y: auto; padding-right: 1rem; }
.list-names ul { list-style-type: none; margin: 0; padding: 0; }
.list-names li { padding: 0.8rem; cursor: pointer; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; border: 1px solid transparent; }
.list-names li:hover { background-color: #f0f4ff; }
.list-names li.active { background-color: var(--primary-color); color: white; border-color: var(--primary-color); }
.delete-list-btn { background: none; border: none; color: inherit; font-size: 1.2rem; cursor: pointer; opacity: 0.5; }
.delete-list-btn:hover { opacity: 1; }
.list-editor { flex-grow: 1; display: flex; flex-direction: column; }
.list-editor textarea { width: 100%; height: 100%; font-family: monospace; resize: none; border: 1px solid var(--border-color); border-radius: 5px; padding: 0.5rem; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; }
</style>