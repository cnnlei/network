<script setup>
import { ref, onMounted, watch } from 'vue';

// --- Reactive State ---
const activeTab = ref('status');
const tlsConfig = ref({
  Enabled: false,
  CertDirectory: '',
  Manual: [],
  ACME: { Enabled: false, Accounts: [] }
});

const isAcmeModalOpen = ref(false);
const acmeModalMode = ref('add');
const currentAcmeAccount = ref(null);
const newDomainForAcme = ref('');

const isManualModalOpen = ref(false);
const manualModalMode = ref('add');
const currentManualCert = ref(null);
const newDomainForManual = ref('');


const certificateList = ref([]);
const isLoadingCerts = ref(false);

// Log Viewer State
const isLogModalOpen = ref(false);
const isLoadingModalLogs = ref(false);
const logsForModal = ref([]);
const logModalDomain = ref('');

// --- NEW: Paginated Cert Manager Logs State ---
const certManagerLogs = ref([]);
const isLoadingCertManagerLogs = ref(false);
const certManagerCurrentPage = ref(1);
const certManagerPageSize = ref(50);
const certManagerTotalPages = ref(1);
const certManagerTotalLogs = ref(0);
const certManagerJumpToPage = ref(1);

const getApiUrl = (endpoint) => `http://${window.location.hostname}:8080${endpoint}`;

// --- NEW: Paginated Log Fetching ---
const fetchCertManagerLogs = async () => {
    isLoadingCertManagerLogs.value = true;
    try {
        const response = await fetch(getApiUrl(`/api/logs/cert-manager?page=${certManagerCurrentPage.value}&pageSize=${certManagerPageSize.value}`));
        if (response.ok) {
            const data = await response.json();
            certManagerLogs.value = data.logs || [];
            certManagerTotalPages.value = data.totalPages;
            certManagerTotalLogs.value = data.totalLogs;
            certManagerJumpToPage.value = certManagerCurrentPage.value;
        } else {
            certManagerLogs.value = ['加载日志失败: ' + await response.text()];
        }
    } catch (e) {
        certManagerLogs.value = ['请求日志失败: ' + e.message];
    } finally {
        isLoadingCertManagerLogs.value = false;
    }
};

watch(activeTab, (newTab) => {
    if (newTab === 'logs') {
        fetchCertManagerLogs();
    }
});

watch(certManagerPageSize, () => {
    certManagerCurrentPage.value = 1;
    fetchCertManagerLogs();
});


// --- API Methods ---
const fetchCertificateStatus = async () => {
  isLoadingCerts.value = true;
  certificateList.value = [];
  try {
    const response = await fetch(getApiUrl('/api/tls/certificates'));
    if (response.ok) {
      certificateList.value = await response.json() || [];
    }
  } catch (error) {
    console.error('获取证书状态请求失败:', error);
  } finally {
    isLoadingCerts.value = false;
  }
};

const fetchTlsConfig = async () => {
  try {
    const response = await fetch(getApiUrl('/api/tls'));
    if (response.ok) {
      const data = await response.json();
      tlsConfig.value = data || {};
      if (!tlsConfig.value.Manual) tlsConfig.value.Manual = [];
      if (!tlsConfig.value.ACME) tlsConfig.value.ACME = { Enabled: false, Accounts: [] };
      if (!tlsConfig.value.ACME.Accounts) tlsConfig.value.ACME.Accounts = [];
    }
  } catch (error) { console.error('加载TLS配置失败:', error); }
};

const saveTlsConfig = async () => {
  if (!confirm('确定要保存设置吗？此操作将热重载TLS配置。\n（注意：全局启用/禁用TLS开关的变更仍需重启程序才能生效）')) return;
  try {
    const response = await fetch(getApiUrl('/api/tls'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tlsConfig.value)
    });
    const result = await response.json();
    alert(result.message || result.error);
    if (response.ok) {
        await fetchTlsConfig();
        await fetchCertificateStatus();
    }
  } catch (error) { alert('请求失败'); }
};

// --- ACME Account Modal Logic ---
const openAcmeAccountModal = (mode, account = null) => {
    acmeModalMode.value = mode;
    if (mode === 'add') {
        currentAcmeAccount.value = {
            Name: '', Provider: 'cloudflare', Email: '', Domains: [],
            Cloudflare: { Email: '', APIKey: '', APIToken: '' }
        };
    } else {
        currentAcmeAccount.value = JSON.parse(JSON.stringify(account));
        if (!currentAcmeAccount.value.Cloudflare) {
          currentAcmeAccount.value.Cloudflare = { Email: '', APIKey: '', APIToken: '' };
        }
    }
    isAcmeModalOpen.value = true;
};
const handleAcmeAccountSubmit = () => {
    if (!currentAcmeAccount.value.Name) {
        alert("账户名称不能为空！");
        return;
    }
    if (acmeModalMode.value === 'add') {
        if (tlsConfig.value.ACME.Accounts.some(acc => acc.Name === currentAcmeAccount.value.Name)) {
            alert("账户名称已存在！");
            return;
        }
        tlsConfig.value.ACME.Accounts.push(currentAcmeAccount.value);
    } else {
        const index = tlsConfig.value.ACME.Accounts.findIndex(acc => acc.Name === currentAcmeAccount.value.Name);
        if (index !== -1) {
            tlsConfig.value.ACME.Accounts[index] = currentAcmeAccount.value;
        }
    }
    isAcmeModalOpen.value = false;
};
const removeAcmeAccount = (accountName) => {
    if (confirm(`确定要删除ACME账户 "${accountName}" 吗？`)) {
        tlsConfig.value.ACME.Accounts = tlsConfig.value.ACME.Accounts.filter(acc => acc.Name !== accountName);
    }
};
const addDomainToAcmeAccount = () => {
  if (newDomainForAcme.value && !currentAcmeAccount.value.Domains.includes(newDomainForAcme.value)) {
    currentAcmeAccount.value.Domains.push(newDomainForAcme.value);
    newDomainForAcme.value = '';
  }
};
const removeDomainFromAcmeAccount = (domain) => {
  currentAcmeAccount.value.Domains = currentAcmeAccount.value.Domains.filter(d => d !== domain);
};

// --- Manual Cert Modal Logic ---
const openManualModal = (mode, cert = null) => {
    manualModalMode.value = mode;
    if (mode === 'add') {
        currentManualCert.value = { Domains: [], CertPath: '', KeyPath: '' };
    } else {
        currentManualCert.value = JSON.parse(JSON.stringify(cert));
    }
    isManualModalOpen.value = true;
};
const handleManualSubmit = () => {
    if (manualModalMode.value === 'add') {
        tlsConfig.value.Manual.push(currentManualCert.value);
    } else {
        const index = tlsConfig.value.Manual.findIndex(c => c.CertPath === currentManualCert.value.CertPath && c.KeyPath === currentManualCert.value.KeyPath);
        if (index !== -1) {
            tlsConfig.value.Manual[index] = currentManualCert.value;
        }
    }
    isManualModalOpen.value = false;
};
const removeManualCert = (cert) => {
    if (confirm(`确定要移除这个手动证书配置吗？`)) {
        tlsConfig.value.Manual = tlsConfig.value.Manual.filter(c => !(c.CertPath === cert.CertPath && c.KeyPath === cert.KeyPath));
    }
};
const addDomainToManualCert = () => {
  if (newDomainForManual.value && !currentManualCert.value.Domains.includes(newDomainForManual.value)) {
    currentManualCert.value.Domains.push(newDomainForManual.value);
    newDomainForManual.value = '';
  }
};
const removeDomainFromManualCert = (domain) => {
  currentManualCert.value.Domains = currentManualCert.value.Domains.filter(d => d !== domain);
};

// --- Certificate Actions ---
const requestCertificate = async (domain) => {
    if (!confirm(`确定要为域名 ${domain} 申请/续订证书吗？\n\n操作将在后台执行，请稍后在“申请日志”标签页或点击此域名的“日志”按钮查看结果。`)) return;
    activeTab.value = 'logs';
    try {
        const response = await fetch(getApiUrl(`/api/tls/request-cert?domain=${domain}`), { method: 'POST' });
        const result = await response.json();
        alert(result.message + ' 列表将在短暂延迟后刷新，您也可以稍后手动刷新。');
        
        setTimeout(() => {
          fetchCertificateStatus();
        }, 5000);

    } catch (error) { 
        alert('请求失败'); 
    }
}

const openLogModal = async (domain) => {
    logModalDomain.value = domain;
    isLogModalOpen.value = true;
    isLoadingModalLogs.value = true;
    logsForModal.value = [];
    try {
        const response = await fetch(getApiUrl(`/api/logs/domain/${domain}`));
        if(response.ok) {
            logsForModal.value = await response.json();
        } else {
            logsForModal.value = ['加载日志失败: ' + await response.text()];
        }
    } catch (e) {
        logsForModal.value = ['请求日志失败: ' + e.message];
    } finally {
        isLoadingModalLogs.value = false;
    }
}

// --- Formatting & Parsing Helpers ---
const formatDate = (dateString) => {
  if (!dateString || dateString.startsWith('0001-01-01')) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
};

const getStatusClass = (status, daysLeft) => {
  if (!['Issued', 'OK'].includes(status)) return 'failed';
  if (daysLeft <= 0) return 'expired';
  if (daysLeft < 30) return 'expiring-soon';
  return 'valid';
};

const getStatusText = (status, daysLeft) => {
  if (status === 'File Not Found') return '证书文件未找到';
  if (status !== 'Issued') return status;
  if (daysLeft <= 0) return '已过期';
  return `剩余 ${daysLeft} 天`;
};


const logLineRegex = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) (\[.*?\]) (.*)$/s;
const legoLogRegex = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(INFO|WARN|ERROR)\]\s*(\[.*?\])?\s?(acme:.*)$/s;

const parseLogLine = (line) => {
    let match = line.match(legoLogRegex);
    if (match) {
        return { timestamp: match[1], level: match[2], tag: match[3] || '', message: match[4] };
    }
    match = line.match(logLineRegex);
    if (match) {
        let level = 'INFO';
        const tagUpper = match[2].toUpperCase();
        if (tagUpper.includes("WARN")) level = 'WARN';
        if (tagUpper.includes("ERROR")) level = 'ERROR';
        return { timestamp: match[1], level: level, tag: match[2], message: match[3] };
    }
    return { timestamp: '', level: 'RAW', tag: '', message: line };
};

const getLogLevelClass = (level) => {
    if (level === 'WARN') return 'log-warn';
    if (level === 'ERROR') return 'log-error';
    return 'log-info';
}

const handleCertManagerJump = () => {
    const page = parseInt(certManagerJumpToPage.value, 10);
    if (!isNaN(page) && page > 0 && page <= certManagerTotalPages.value) {
        certManagerCurrentPage.value = page;
        fetchCertManagerLogs();
    } else {
        certManagerJumpToPage.value = certManagerCurrentPage.value;
    }
}

// --- Lifecycle Hooks ---
onMounted(() => {
  fetchTlsConfig();
  fetchCertificateStatus();
});
</script>

<template>
  <div>
    <div class="panel">
      <div class="panel-header">
        <h2>SSL/TLS 证书管理</h2>
      </div>

      <div class="tabs">
        <button :class="{ active: activeTab === 'status' }" @click="activeTab = 'status'">证书状态</button>
        <button :class="{ active: activeTab === 'settings' }" @click="activeTab = 'settings'">证书设置</button>
        <button :class="{ active: activeTab === 'logs' }" @click="activeTab = 'logs'">申请日志</button>
      </div>

      <div class="tab-content">
        <div v-if="activeTab === 'status'">
          <div class="section-header">
            <h4>证书托管列表</h4>
            <button @click="fetchCertificateStatus" class="btn-refresh" :disabled="isLoadingCerts">
              {{ isLoadingCerts ? '加载中...' : '刷新' }}
            </button>
          </div>
          <div v-if="isLoadingCerts" class="empty-state-small">正在加载...</div>
          <table v-else class="cert-table">
            <thead>
              <tr>
                <th>域名</th>
                <th>类型</th>
                <th>状态</th>
                <th>到期时间</th>
                <th>颁发机构</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!certificateList || certificateList.length === 0">
                  <td colspan="6" class="empty-state-small">暂无域名配置，请前往“证书设置”标签页添加。</td>
              </tr>
              <tr v-for="cert in certificateList" :key="cert.Domain">
                <td>{{ cert.Domain }}</td>
                <td><span class="type-badge" :class="cert.Type.toLowerCase()">{{ cert.Type }}</span></td>
                <td><span :class="['status-badge', getStatusClass(cert.Status, cert.DaysLeft)]">{{ getStatusText(cert.Status, cert.DaysLeft) }}</span></td>
                <td>{{ formatDate(cert.NotAfter) }}</td>
                <td>
                  <span :class="{ 'staging-issuer': cert.IsStaging }">
                    {{ cert.Issuer || 'N/A' }} {{ cert.IsStaging ? '(测试)' : '' }}
                  </span>
                </td>
                <td class="actions-cell">
                    <button v-if="cert.Type === 'ACME'" @click="requestCertificate(cert.Domain)" class="btn-action">{{ cert.Status === 'Issued' ? '续签' : '申请' }}</button>
                    <button v-if="cert.Type === 'ACME'" @click="openLogModal(cert.Domain)" class="btn-action btn-logs">日志</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="activeTab === 'settings'">
          <div class="form-group toggle-group">
              <label for="tls-enabled">全局启用 TLS (需重启生效)</label>
              <input type="checkbox" id="tls-enabled" v-model="tlsConfig.Enabled" class="main-toggle">
          </div>
          <p class="description">全局开关。开启或关闭此功能需要重启整个程序才能生效。</p>

          <template v-if="tlsConfig.Enabled">
              <div class="form-section">
                  <h4>证书存储</h4>
                  <div class="form-group">
                      <label for="cert-dir">证书存放目录</label>
                      <input type="text" id="cert-dir" v-model="tlsConfig.CertDirectory">
                      <p class="description">所有自动申请或上传的证书都将存放在此目录。默认为程序根目录下的 `certs` 文件夹。</p>
                  </div>
              </div>

              <div class="form-section">
                  <div class="section-header">
                      <h4>手动证书配置</h4>
                      <button @click="openManualModal('add')" class="btn-primary">+ 添加手动证书</button>
                  </div>
                  <div v-if="!tlsConfig.Manual || tlsConfig.Manual.length === 0" class="empty-state-small">暂无手动证书配置。</div>
                  <div v-else class="account-list">
                      <div v-for="(cert, index) in tlsConfig.Manual" :key="index" class="account-item">
                          <div class="account-header">
                              <strong>{{ cert.Domains.join(', ') || '未指定域名' }}</strong>
                              <div class="cert-path-display">{{ cert.CertPath }}</div>
                          </div>
                          <div class="account-actions">
                              <button @click="openManualModal('edit', cert)" class="btn-action">编辑</button>
                              <button @click="removeManualCert(cert)" class="btn-action-danger">删除</button>
                          </div>
                      </div>
                  </div>
              </div>

              <div class="form-section">
                  <h4>ACME 自动证书 (Let's Encrypt)</h4>
                  <div class="form-group toggle-group">
                      <label for="acme-enabled">启用 ACME</label>
                      <input type="checkbox" id="acme-enabled" v-model="tlsConfig.ACME.Enabled" class="main-toggle">
                  </div>
                  <template v-if="tlsConfig.ACME.Enabled">
                      <div class="section-header">
                          <h5>ACME 账户列表</h5>
                          <button @click="openAcmeAccountModal('add')" class="btn-primary">+ 添加ACME账户</button>
                      </div>
                      <div v-if="!tlsConfig.ACME.Accounts || tlsConfig.ACME.Accounts.length === 0" class="empty-state-small">暂无ACME账户，请添加一个。</div>
                      <div v-else class="account-list">
                          <div v-for="account in tlsConfig.ACME.Accounts" :key="account.Name" class="account-item">
                              <div class="account-header">
                                  <strong>{{ account.Name }}</strong> ({{ account.Provider }})
                                  <span>{{ account.Email }}</span>
                              </div>
                              <div class="account-domains">管理 {{ account.Domains.length }} 个域名</div>
                              <div class="account-actions">
                                  <button @click="openAcmeAccountModal('edit', account)" class="btn-action">编辑</button>
                                  <button @click="removeAcmeAccount(account.Name)" class="btn-action-danger">删除</button>
                              </div>
                          </div>
                      </div>
                  </template>
              </div>
          </template>
          <div class="form-actions">
              <button @click="saveTlsConfig" class="btn btn-primary">保存所有设置 (热重载)</button>
          </div>
        </div>

        <div v-if="activeTab === 'logs'">
            <h4>证书服务日志 (共 {{ certManagerTotalLogs }} 条)</h4>
            <p class="description">这里会显示所有与证书申请、续订、加载相关的日志。</p>
            <div v-if="isLoadingCertManagerLogs" class="empty-state-small">正在加载日志...</div>
            <div v-else>
                <div class="logs-container">
                    <div v-if="certManagerLogs.length === 0" class="empty-state-small">暂无相关日志记录。</div>
                    <div v-else v-for="(line, index) in certManagerLogs" :key="index" class="log-line">
                        <span class="log-time">{{ parseLogLine(line).timestamp }}</span>
                        <span :class="['log-level', getLogLevelClass(parseLogLine(line).level)]">{{ parseLogLine(line).level }}</span>
                        <span class="log-tag">{{ parseLogLine(line).tag }}</span>
                        <span class="log-message">{{ parseLogLine(line).message }}</span>
                    </div>
                </div>
                <div class="pagination-controls-footer">
                    <select v-model="certManagerPageSize">
                        <option :value="50">50 条/页</option>
                        <option :value="100">100 条/页</option>
                        <option :value="200">200 条/页</option>
                        <option :value="500">500 条/页</option>
                    </select>
                    <button @click="certManagerCurrentPage > 1 && (certManagerCurrentPage--, fetchCertManagerLogs())" :disabled="certManagerCurrentPage <= 1">上一页</button>
                    <div class="page-jump">
                        第
                        <input type="number" v-model.number="certManagerJumpToPage" @keyup.enter="handleCertManagerJump" min="1" :max="certManagerTotalPages">
                        / {{ certManagerTotalPages }} 页
                    </div>
                    <button @click="certManagerCurrentPage < certManagerTotalPages && (certManagerCurrentPage++, fetchCertManagerLogs())" :disabled="certManagerCurrentPage >= certManagerTotalPages">下一页</button>
                </div>
            </div>
        </div>
      </div>
    </div>

    <div v-if="isAcmeModalOpen" class="modal-overlay" @click.self="isAcmeModalOpen = false">
        <div class="modal-content large">
            <h2>{{ acmeModalMode === 'add' ? '添加新 ACME 账户' : '编辑 ACME 账户' }}</h2>
            <form @submit.prevent="handleAcmeAccountSubmit" v-if="currentAcmeAccount">
                <div class="form-section">
                  <div class="form-group">
                      <label>账户名称 (唯一标识)</label>
                      <input type="text" v-model="currentAcmeAccount.Name" :disabled="acmeModalMode === 'edit'" required>
                  </div>
                  <div class="form-group">
                      <label>ACME 账户邮箱</label>
                      <input type="email" v-model="currentAcmeAccount.Email" required>
                  </div>
                  <div class="form-group">
                      <label>DNS 提供商</label>
                      <select v-model="currentAcmeAccount.Provider">
                          <option value="cloudflare">Cloudflare</option>
                      </select>
                  </div>
                </div>

                <div class="form-section" v-if="currentAcmeAccount.Provider === 'cloudflare'">
                    <h5>Cloudflare API 设置</h5>
                    <div class="form-group">
                        <label>Cloudflare 账户邮箱 (可选)</label>
                        <input type="email" v-model="currentAcmeAccount.Cloudflare.Email">
                    </div>
                    <div class="form-group">
                        <label>Cloudflare 全局 API Key (可选)</label>
                        <input type="password" v-model="currentAcmeAccount.Cloudflare.APIKey">
                    </div>
                    <div class="form-group">
                        <label>Cloudflare API Token (推荐)</label>
                        <input type="password" v-model="currentAcmeAccount.Cloudflare.APIToken">
                        <p class="description">拥有 DNS:Edit 和 Zone:Read 权限的 API Token。</p>
                    </div>
                </div>

                <div class="form-section">
                    <h5>域名管理</h5>
                    <div class="domain-list">
                      <div v-if="!currentAcmeAccount.Domains || currentAcmeAccount.Domains.length === 0" class="empty-state-small">暂无域名</div>
                      <div v-for="domain in currentAcmeAccount.Domains" :key="domain" class="domain-item">
                          <span>{{ domain }}</span>
                          <button @click.prevent="removeDomainFromAcmeAccount(domain)" class="btn-action-danger">移除</button>
                      </div>
                    </div>
                    <div class="add-domain-form">
                        <input type="text" v-model="newDomainForAcme" placeholder="例如 www.example.com" @keyup.enter.prevent="addDomainToAcmeAccount">
                        <button @click.prevent="addDomainToAcmeAccount" class="btn-primary">添加</button>
                    </div>
                </div>

                <div class="form-actions">
                    <button type="button" class="btn-cancel" @click="isAcmeModalOpen = false">取消</button>
                    <button type="submit" class="btn-save">{{ acmeModalMode === 'add' ? '创建账户' : '保存更改' }}</button>
                </div>
            </form>
        </div>
    </div>

    <div v-if="isManualModalOpen" class="modal-overlay" @click.self="isManualModalOpen = false">
        <div class="modal-content large">
            <h2>{{ manualModalMode === 'add' ? '添加手动证书' : '编辑手动证书' }}</h2>
            <form @submit.prevent="handleManualSubmit" v-if="currentManualCert">
                <div class="form-section">
                    <div class="form-group">
                        <label>证书文件路径 (.pem / .crt)</label>
                        <input type="text" v-model="currentManualCert.CertPath" required>
                    </div>
                    <div class="form-group">
                        <label>私钥文件路径 (.key)</label>
                        <input type="text" v-model="currentManualCert.KeyPath" required>
                    </div>
                </div>

                <div class="form-section">
                    <h5>应用的域名</h5>
                    <p class="description">此证书将应用于以下列出的域名。当收到这些域名的请求时，将优先使用此证书。</p>
                    <div class="domain-list">
                        <div v-if="!currentManualCert.Domains || currentManualCert.Domains.length === 0" class="empty-state-small">暂无域名</div>
                        <div v-for="domain in currentManualCert.Domains" :key="domain" class="domain-item">
                            <span>{{ domain }}</span>
                            <button @click.prevent="removeDomainFromManualCert(domain)" class="btn-action-danger">移除</button>
                        </div>
                    </div>
                    <div class="add-domain-form">
                        <input type="text" v-model="newDomainForManual" placeholder="例如 www.example.com" @keyup.enter.prevent="addDomainToManualCert">
                        <button @click.prevent="addDomainToManualCert" class="btn-primary">添加</button>
                    </div>
                </div>

                <div class="form-actions">
                    <button type="button" class="btn-cancel" @click="isManualModalOpen = false">取消</button>
                    <button type="submit" class="btn-save">保存</button>
                </div>
            </form>
        </div>
    </div>
    
    <div v-if="isLogModalOpen" class="modal-overlay" @click.self="isLogModalOpen = false">
      <div class="modal-content large">
        <h2>日志: {{ logModalDomain }}</h2>
        <div v-if="isLoadingModalLogs" class="empty-state-small">加载中...</div>
        <div v-else class="logs-container-modal">
            <div v-if="logsForModal.length === 0" class="empty-state-small">该域名下暂无相关日志记录。</div>
            <div v-else v-for="(line, index) in logsForModal" :key="index" class="log-line">
                <span class="log-time">{{ parseLogLine(line).timestamp }}</span>
                <span :class="['log-level', getLogLevelClass(parseLogLine(line).level)]">{{ parseLogLine(line).level }}</span>
                <span class="log-tag">{{ parseLogLine(line).tag }}</span>
                <span class="log-message">{{ parseLogLine(line).message }}</span>
            </div>
        </div>
        <div class="form-actions">
            <button type="button" class="btn-cancel" @click="isLogModalOpen = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.panel { background-color: #ffffff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
.panel-header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 1rem; }
.panel-header h2 { margin: 0; font-size: 1.4rem; }
.tabs { display: flex; border-bottom: 1px solid #e0e0e0; margin-bottom: 1.5rem; }
.tabs button { padding: 0.8rem 1.2rem; border: none; background-color: transparent; cursor: pointer; font-size: 1rem; position: relative; color: #6c757d; border-bottom: 3px solid transparent; margin-bottom: -1px; }
.tabs button.active { color: #007bff; font-weight: 600; border-bottom-color: #007bff; }
.tab-content { padding-top: 1rem; }
.btn { border: none; padding: 0.7rem 1.5rem; border-radius: 5px; cursor: pointer; font-size: 1rem; font-weight: 500; transition: background-color 0.2s; }
.btn-primary { background-color: #007bff; color: white; }
.btn-primary:hover { background-color: #0056b3; }
.form-section { border-left: 3px solid #f0f0f0; padding-left: 1.5rem; margin-bottom: 2rem; }
.form-section h4, .form-section h5 { margin-top: 0; margin-bottom: 1.5rem; }
.form-group { margin-bottom: 1.5rem; }
.form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
.form-group input[type="text"], .form-group input[type="email"], .form-group input[type="password"], .form-group select { width: 100%; max-width: 500px; padding: 0.7rem; border: 1px solid #e0e0e0; border-radius: 5px; box-sizing: border-box; }
.toggle-group { display: flex; align-items: center; gap: 1rem; }
.main-toggle { width: 20px; height: 20px; }
.description { font-size: 0.9rem; color: #6c757d; margin-top: 0.5rem; max-width: 500px; }
.domain-list { border: 1px solid #e0e0e0; border-radius: 5px; max-width: 600px; margin-bottom: 1rem; }
.domain-item { display: flex; justify-content: space-between; align-items: center; padding: 0.8rem 1rem; }
.domain-item:not(:last-child) { border-bottom: 1px solid #e0e0e0; }
.add-domain-form { display: flex; gap: 1rem; max-width: 600px; }
.add-domain-form input { flex-grow: 1; }
.btn-action { background-color: #e9ecef; color: #495057; border: 1px solid #ced4da; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; }
.btn-action:hover { background-color: #d2d6da; }
.btn-action-danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; margin-left: 0.5rem;}
.btn-action-danger:hover { background-color: #f1b0b7; }
.empty-state-small { text-align: center; padding: 1rem; color: #999; }
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.btn-refresh { background-color: #f8f9fa; border: 1px solid #dee2e6; color: #343a40; padding: 0.5rem 1rem; border-radius: 5px; cursor: pointer; font-size: 0.9rem; }
.btn-refresh:disabled { opacity: 0.6; cursor: not-allowed; }
.cert-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
.cert-table th, .cert-table td { padding: 0.8rem 1rem; text-align: left; border-bottom: 1px solid #f0f0f0; }
.cert-table th { background-color: #f8f9fa; font-weight: 500; }
.staging-issuer { color: #ffc107; font-weight: bold; }
.status-badge { padding: 0.3rem 0.6rem; border-radius: 12px; font-size: 0.8rem; color: white; white-space: nowrap; }
.status-badge.valid { background-color: #28a745; }
.status-badge.expiring-soon { background-color: #ffc107; color: #333; }
.status-badge.expired { background-color: #dc3545; }
.status-badge.failed { background-color: #721c24; }
.type-badge { padding: 0.3rem 0.6rem; border-radius: 12px; font-size: 0.8rem; }
.type-badge.acme { background-color: #d1ecf1; color: #0c5460; }
.type-badge.manual { background-color: #e2e3e5; color: #383d41; }
.form-actions { display: flex; justify-content: flex-end; margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid #eee; }
.logs-container, .logs-container-modal { background-color: #282c34; color: #dcdfe4; border-radius: 5px; height: 50vh; overflow-y: auto; white-space: pre-wrap; word-break: break-word; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.85rem; padding: 1rem; }
.modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6); display: flex; justify-content: center; align-items: center; z-index: 1000; }
.modal-content { background-color: white; padding: 1.5rem 2rem; border-radius: 8px; width: 100%; max-width: 600px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
.modal-content.large { max-width: 80vw; max-height: 90vh; display: flex; flex-direction: column; }
.modal-content.large form { overflow-y: auto; padding-right: 1rem; }
.logs-container-modal { height: 60vh; margin-bottom: 1rem; }
.btn-cancel { background-color: #6c757d; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.btn-save { background-color: #28a745; color: white; border: none; padding: 0.7rem 1.5rem; border-radius: 5px; font-weight: 500; }
.actions-cell { text-align: right; }
.btn-logs { margin-left: 0.5rem; background-color: #6c757d; color: white; border-color: #6c757d; }
.btn-logs:hover { background-color: #5a6268; }
.log-line { display: flex; flex-wrap: nowrap; gap: 1rem; align-items: baseline;}
.log-time { color: #999; flex-shrink: 0; }
.log-level { font-weight: bold; flex-shrink: 0; text-align: center; width: 50px; }
.log-level.log-info { color: #87cefa; }
.log-level.log-warn { color: #ffd700; }
.log-level.log-error { color: #f08080; }
.log-tag { color: #add8e6; flex-shrink: 0; }
.log-message { flex-grow: 1; }
.account-list { display: flex; flex-direction: column; gap: 1rem; }
.account-item { border: 1px solid #e0e0e0; border-radius: 5px; padding: 1rem; display: flex; justify-content: space-between; align-items: center; }
.account-header { display: flex; flex-direction: column; gap: 0.25rem; }
.account-domains { color: #6c757d; font-size: 0.9rem; }
.account-actions { display: flex; gap: 0.5rem; }
.cert-path-display { font-size: 0.8rem; color: #6c757d; font-family: monospace; }
.pagination-controls-footer { display: flex; justify-content: center; align-items: center; gap: 10px; padding-top: 1rem; border-top: 1px solid #e0e0e0; margin-top: 1rem;}
.pagination-controls-footer button, .pagination-controls-footer select { padding: 0.5rem 1rem; border-radius: 5px; border: 1px solid #ccc; background-color: #f8f9fa; cursor: pointer; }
.pagination-controls-footer button:disabled { opacity: 0.6; cursor: not-allowed; }
.page-jump { display: flex; align-items: center; gap: 5px; }
.page-jump input { width: 50px; text-align: center; padding: 0.5rem; border-radius: 5px; border: 1px solid #ccc; }
.page-jump input::-webkit-outer-spin-button, .page-jump input::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.page-jump input[type=number] { -moz-appearance: textfield; }
</style>