<script setup>
import { ref, onMounted } from 'vue';

const settings = ref({
  LogDirectory: '',
  IPListDirectory: '',
  // ConfigDirectory is no longer part of the editable settings
});

const configFilePath = ref('加载中...'); // 用于显示只读的配置文件路径

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

const fetchSettings = async () => {
  try {
    const response = await fetch(getApiUrl('/api/settings'));
    if (response.ok) {
      const data = await response.json();
      settings.value = data;
      // 假设后端会返回一个字段来告知前端配置文件的路径
      // 如果没有，我们可以暂时显示一个通用消息
      configFilePath.value = data.ConfigFilePath || "通过 -config 命令行参数指定";
    }
  } catch (error) {
    console.error('加载设置失败:', error);
    alert('加载设置失败！');
  }
};

const saveSettings = async () => {
  if (!confirm('确定要保存这些路径设置吗？所有设置都需要重启程序才能生效。')) {
    return;
  }
  
  try {
    const response = await fetch(getApiUrl('/api/settings'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings.value)
    });
    const result = await response.json();
    if (response.ok) {
      alert(result.message || '设置已保存！');
      fetchSettings();
    } else {
      alert(`保存失败: ${result.error}`);
    }
  } catch (error) {
    alert('请求失败');
  }
};

onMounted(() => {
  fetchSettings();
});
</script>

<template>
  <div>
    <div class="panel settings-panel">
      <div class="panel-header">
        <h2>系统设置</h2>
        <button @click="saveSettings" class="btn btn-primary">保存设置</button>
      </div>
      
      <div class="form-container">
        <div class="form-group">
          <label>配置文件 (config.yml) 路径</label>
          <input type="text" :value="configFilePath" disabled>
          <p class="description">此路径由程序启动时的 `-config` 命令行参数决定，无法在此处修改。</p>
        </div>

        <div class="form-group">
          <label for="log-dir">日志文件 (forwarder.log) 存放目录</label>
          <input id="log-dir" type="text" v-model="settings.LogDirectory" placeholder="例如 /var/log/forwarder/">
          <p class="description">指定日志文件的存放位置。**此项修改需要重启程序才能生效。**</p>
        </div>
        
        <div class="form-group">
          <label for="iplist-dir">IP名单缓存目录</label>
          <input id="iplist-dir" type="text" v-model="settings.IPListDirectory" placeholder="例如 /var/lib/forwarder/ip_lists/">
          <p class="description">用于存放从国家IP和URL下载的IP名单文件，作为本地缓存。**此项修改需要重启程序才能生效。**</p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid #e0e0e0; }
.panel-header h2 { margin: 0; font-size: 1.4rem; }
.btn { background-color: #007bff; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; cursor: pointer; font-size: 1rem; font-weight: 500; transition: background-color 0.2s; }
.settings-panel { border-left: 4px solid #6f42c1; }
.form-container { max-width: 700px; }
.form-group { margin-bottom: 2rem; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; font-size: 1.1rem; }
.form-group input { width: 100%; padding: 0.8rem; border: 1px solid #e0e0e0; border-radius: 5px; font-size: 1rem; box-sizing: border-box; }
.form-group input:disabled { background-color: #e9ecef; cursor: not-allowed; }
.description { font-size: 0.9rem; color: #6c757d; margin-top: 0.75rem; }
</style>