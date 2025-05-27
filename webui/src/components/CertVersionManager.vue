<script setup>
import { ref, onMounted } from 'vue'
import API_CONFIG from '../utils/config.js'
import Dialog from './Dialog.vue'

const currentVersion = ref(null) // 当前使用的版本
const isLoading = ref(false)
const apiUrl = API_CONFIG.BASE_URL

// 对话框状态
const dialogVisible = ref(false)
const dialogTitle = ref('提示')
const dialogMessage = ref('')
const dialogType = ref('alert') // alert 或 confirm
const pendingVersion = ref(null) // 待切换的版本

// 证书版本数据
const certVersions = [
  {
    version: 1,
    name: 'CERT_V1',
    description: '基础版证书格式，不包含扩展字段',
    fields: [
      { name: 'Version', type: '1字节', description: '证书版本号' },
      { name: 'SerialNum', type: '9字节', description: '证书序列号，例如"SN000001"' },
      { name: 'IssuerID', type: '5字节', description: '颁发者ID，例如"CA01"' },
      { name: 'SubjectID', type: '5字节', description: '主体ID，例如"U001"' },
      { name: 'Validity', type: '16字节', description: '有效期，包含起止日期' },
      { name: 'PubKey', type: '33字节', description: '公钥重构值' }
    ],
  },
  {
    version: 2,
    name: 'CERT_V2',
    description: '增强版证书格式，包含扩展字段',
    fields: [
      { name: 'Version', type: '1字节', description: '证书版本号' },
      { name: 'SerialNum', type: '9字节', description: '证书序列号，例如"SN000001"' },
      { name: 'IssuerID', type: '5字节', description: '颁发者ID，例如"CA01"' },
      { name: 'SubjectID', type: '5字节', description: '主体ID，例如"U001"' },
      { name: 'Validity', type: '16字节', description: '有效期，包含起止日期' },
      { name: 'PubKey', type: '33字节', description: '公钥重构值' },
    ],
    extensionFields: [
      { name: 'Usage', type: '1字节', description: '证书用途（身份认证/加密/签名等）' },
      { name: 'SignAlg', type: '1字节', description: '签名算法（SM2）' },
      { name: 'HashAlg', type: '1字节', description: '哈希算法（SM3）' },
      { name: 'ExtraInfo', type: '11字节', description: '额外信息字段' }
    ],
  }
]

// 显示提示对话框
const showAlert = (message, title = '提示') => {
  dialogType.value = 'alert'
  dialogTitle.value = title
  dialogMessage.value = message
  dialogVisible.value = true
}

// 显示确认对话框
const showConfirm = (message, title = '确认') => {
  return new Promise((resolve) => {
    dialogType.value = 'confirm'
    dialogTitle.value = title
    dialogMessage.value = message
    dialogVisible.value = true
    
    // 临时保存确认和取消回调
    window.confirmResolve = resolve
  })
}

// 对话框确认回调
const handleDialogConfirm = () => {
  if (window.confirmResolve) {
    window.confirmResolve(true)
    window.confirmResolve = null
  }
  
  // 如果是切换版本的确认
  if (pendingVersion.value !== null) {
    doSetVersion(pendingVersion.value)
    pendingVersion.value = null
  }
}

// 对话框取消回调
const handleDialogCancel = () => {
  if (window.confirmResolve) {
    window.confirmResolve(false)
    window.confirmResolve = null
  }
  
  // 清除待切换版本
  if (pendingVersion.value !== null) {
    pendingVersion.value = null
  }
}

// 获取当前证书版本
const fetchCurrentVersion = async () => {
  isLoading.value = true
  try {
    const response = await fetch(`${apiUrl}/api/cert-version`)
    
    if (!response.ok) {
      throw new Error(`获取证书版本失败: ${response.status}`)
    }
    
    const data = await response.json()
    currentVersion.value = data.version
  } catch (error) {
    console.error('获取证书版本失败:', error)
    showAlert(`获取证书版本信息失败: ${error.message}`, '错误')
  } finally {
    isLoading.value = false
  }
}

// 设置证书版本入口函数
const setVersion = async (version) => {
  if (version === currentVersion.value) {
    showAlert('已经是当前版本，无需切换')
    return
  }
  
  pendingVersion.value = version
  showConfirm(`确定要将证书版本切换到 V${version} 吗？`, '切换版本')
}

// 实际设置版本的函数
const doSetVersion = async (version) => {
  isLoading.value = true
  try {
    const response = await fetch(`${apiUrl}/api/set-cert-version`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ version })
    })
    
    if (!response.ok) {
      throw new Error(`设置证书版本失败: ${response.status}`)
    }
    
    const data = await response.json()
    if (data.success) {
      currentVersion.value = version
      showAlert(`证书版本已成功切换到 V${version}`, '成功')
    } else {
      throw new Error(data.message || '切换失败')
    }
  } catch (error) {
    console.error('设置证书版本失败:', error)
    showAlert(`设置证书版本失败: ${error.message || '未知错误'}`, '错误')
  } finally {
    isLoading.value = false
  }
}

// 页面加载时获取当前证书版本
onMounted(fetchCurrentVersion)
</script>

<template>
  <div class="cert-version-manager">
    <h1>证书版本管理</h1>
    
    <!-- 当前版本信息 -->
    <div class="current-version">
      <h2>当前使用的证书版本</h2>
      <div v-if="isLoading" class="loading">加载中...</div>
      <div v-else-if="currentVersion" class="version-badge" :class="`v${currentVersion}`">
        V{{ currentVersion }}
      </div>
      <div v-else class="error-text">未能获取当前版本</div>
    </div>
    
    <!-- 版本切换按钮 -->
    <div class="version-switcher">
      <h2>切换证书版本</h2>
      <div class="buttons">
        <button 
          v-for="version in [1, 2]" 
          :key="version"
          :class="[{ active: currentVersion === version, disabled: isLoading }, `v${version}`]"
          @click="setVersion(version)"
          :disabled="isLoading"
        >
          V{{ version }}
        </button>
      </div>
    </div>
    
    <!-- 版本对比表格 -->
    <div class="version-comparison">
      <h2>证书版本对比</h2>
      
      <div class="cards-container">
        <div v-for="cert in certVersions" :key="cert.version" class="version-card" :class="`v${cert.version}`">
          <div class="card-header">
            <h3>{{ cert.name }}</h3>
            <span class="version-pill">V{{ cert.version }}</span>
          </div>
          
          <div class="card-description">{{ cert.description }}</div>
          
          <div class="card-section">
            <h4>基础字段</h4>
            <table>
              <thead>
                <tr>
                  <th>字段名</th>
                  <th>大小</th>
                  <th>说明</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="field in cert.fields" :key="field.name">
                  <td>{{ field.name }}</td>
                  <td><code>{{ field.type }}</code></td>
                  <td>{{ field.description }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          
          <div v-if="cert.extensionFields" class="card-section">
            <h4>扩展字段</h4>
            <table>
              <thead>
                <tr>
                  <th>字段名</th>
                  <th>大小</th>
                  <th>说明</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="field in cert.extensionFields" :key="field.name">
                  <td>{{ field.name }}</td>
                  <td><code>{{ field.type }}</code></td>
                  <td>{{ field.description }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    
    <!-- 自定义对话框组件 -->
    <Dialog
      v-model:visible="dialogVisible"
      :title="dialogTitle"
      :message="dialogMessage"
      :type="dialogType"
      @confirm="handleDialogConfirm"
      @cancel="handleDialogCancel"
    />
  </div>
</template>

<style scoped>
.cert-version-manager {
  padding: 20px;
}

.cert-version-manager h1 {
  margin-bottom: 24px;
  color: #1e293b;
}

.cert-version-manager h2 {
  margin: 24px 0 16px;
  color: #334155;
  font-size: 1.4rem;
}

.current-version {
  background-color: white;
  padding: 24px;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  margin-bottom: 24px;
  text-align: center;
}

.version-badge {
  display: inline-block;
  font-size: 24px;
  font-weight: bold;
  padding: 8px 24px;
  border-radius: 24px;
  color: white;
}

.version-badge.v1 {
  background-color: #3b82f6;
}

.version-badge.v2 {
  background-color: #10b981;
}

.loading {
  color: #64748b;
  font-style: italic;
}

.error-text {
  color: #ef4444;
}

.version-switcher {
  background-color: white;
  padding: 24px;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  margin-bottom: 24px;
}

.buttons {
  display: flex;
  gap: 16px;
}

.buttons button {
  flex: 1;
  padding: 12px;
  font-size: 18px;
  border: 2px solid #e2e8f0;
  background-color: white;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.buttons button:hover:not(.active):not(:disabled) {
  background-color: #f1f5f9;
  border-color: #cbd5e1;
}

.buttons button.active.v1 {
  background-color: #3b82f6;
  color: white;
  border-color: #2563eb;
}

.buttons button.active.v2 {
  background-color: #10b981;
  color: white;
  border-color: #059669;
}

.buttons button:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.version-comparison {
  background-color: white;
  padding: 24px;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.cards-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
}

.version-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 20px;
  transition: transform 0.2s, box-shadow 0.2s;
}

.version-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.version-card.v1 {
  border-top: 4px solid #3b82f6;
}

.version-card.v2 {
  border-top: 4px solid #10b981;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.card-header h3 {
  margin: 0;
  color: #1e293b;
}

.version-pill {
  background-color: #f1f5f9;
  color: #64748b;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 0.9em;
  font-weight: bold;
}

.card-description {
  color: #64748b;
  margin-bottom: 16px;
}

.card-section {
  margin: 20px 0;
}

.card-section h4 {
  color: #475569;
  margin-bottom: 8px;
  font-size: 1.05rem;
  font-weight: 600;
}

.card-section ul {
  padding-left: 20px;
  color: #334155;
}

.card-section li {
  margin: 6px 0;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 8px 0;
  font-size: 0.9em;
}

th {
  background-color: #f8fafc;
  text-align: left;
  padding: 8px;
  border-bottom: 2px solid #e2e8f0;
  color: #475569;
}

td {
  padding: 8px;
  border-bottom: 1px solid #e2e8f0;
  color: #334155;
}

code {
  background: #f1f5f9;
  padding: 2px 4px;
  border-radius: 4px;
  color: #475569;
  font-family: monospace;
}
</style> 