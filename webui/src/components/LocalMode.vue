<script setup>
import { ref, onMounted } from 'vue'
import API_CONFIG from '../utils/config.js'

const operationLog = ref([])
const registerUserId = ref('U0000001')
const updateUserId = ref('U0000001')
const isLoading = ref(false)
const apiUrl = API_CONFIG.BASE_URL

// 添加日志条目
function addLogEntry(message) {
  const timestamp = new Date().toLocaleString('zh-CN')
  operationLog.value.unshift(`[${timestamp}] ${message}`)
}

// 证书注册函数
async function registerCertificate() {
  if (!registerUserId.value) {
    addLogEntry('错误：用户ID不能为空')
    return
  }
  
  if (registerUserId.value.length !== 8) {
    addLogEntry('错误：用户ID必须是8个字符')
    return
  }
  
  try {
    isLoading.value = true
    addLogEntry(`正在为用户 ${registerUserId.value} 生成证书...`)
    
    const response = await fetch(`${apiUrl}/api/local/generate-cert`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId: registerUserId.value
      })
    })
    
    const data = await response.json()
    
    if (data.success) {
      addLogEntry(`成功：用户 ${registerUserId.value} 的证书已生成`)
    } else {
      addLogEntry(`失败：${data.message || '证书生成失败'}`)
    }
  } catch (error) {
    console.error('证书生成错误:', error)
    addLogEntry(`错误：证书生成失败 - ${error.message}`)
  } finally {
    isLoading.value = false
  }
}

// 证书更新函数
async function updateCertificate() {
  if (!updateUserId.value) {
    addLogEntry('错误：用户ID不能为空')
    return
  }
  
  if (updateUserId.value.length !== 8) {
    addLogEntry('错误：用户ID必须是8个字符')
    return
  }
  
  try {
    isLoading.value = true
    addLogEntry(`正在更新用户 ${updateUserId.value} 的证书...`)
    
    const response = await fetch(`${apiUrl}/api/local/update-cert`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId: updateUserId.value
      })
    })
    
    const data = await response.json()
    
    if (data.success) {
      addLogEntry(`成功：用户 ${updateUserId.value} 的证书已更新`)
    } else {
      addLogEntry(`失败：${data.message || '证书更新失败'}`)
    }
  } catch (error) {
    console.error('证书更新错误:', error)
    addLogEntry(`错误：证书更新失败 - ${error.message}`)
  } finally {
    isLoading.value = false
  }
}

onMounted(() => {
  addLogEntry('证书管理页面已加载')
})
</script>

<template>
  <div class="local-mode">
    <div class="header">
      <h1>证书管理</h1>
    </div>
    
    <div class="card-container">
      <!-- 证书注册卡片 -->
      <div class="card function-card">
        <div class="card-header">
          <h2>证书注册</h2>
        </div>
        <div class="card-body">
          <p class="description">
            为用户注册新的数字证书
          </p>
          <div class="input-group">
            <label for="register-user-id">用户ID:</label>
            <input 
              id="register-user-id" 
              v-model="registerUserId" 
              type="text" 
              placeholder="请输入用户ID"
            />
          </div>
          <button 
            @click="registerCertificate" 
            :disabled="!registerUserId || isLoading" 
            class="function-btn"
          >
            <span v-if="isLoading">处理中...</span>
            <span v-else>注册证书</span>
          </button>
        </div>
      </div>
      
      <!-- 证书更新卡片 -->
      <div class="card function-card">
        <div class="card-header">
          <h2>证书更新</h2>
        </div>
        <div class="card-body">
          <p class="description">
            更新用户的现有数字证书
          </p>
          <div class="input-group">
            <label for="update-user-id">用户ID:</label>
            <input 
              id="update-user-id" 
              v-model="updateUserId" 
              type="text" 
              placeholder="请输入用户ID"
            />
          </div>
          <button 
            @click="updateCertificate" 
            :disabled="!updateUserId || isLoading" 
            class="function-btn"
          >
            <span v-if="isLoading">处理中...</span>
            <span v-else>更新证书</span>
          </button>
        </div>
      </div>
    </div>
    
    <div class="card log-card">
      <div class="card-header">
        <h2>操作日志</h2>
      </div>
      <div class="card-body">
        <div v-if="operationLog.length === 0" class="empty-log">
          暂无操作日志
        </div>
        <ul v-else class="log-entries">
          <li v-for="(entry, index) in operationLog" :key="index">
            {{ entry }}
          </li>
        </ul>
      </div>
    </div>
  </div>
</template>

<style scoped>
.local-mode {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

h1 {
  font-size: 24px;
  margin: 0;
  color: #334155;
}

.card {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  margin-bottom: 20px;
  overflow: hidden;
}

.card-container {
  display: flex;
  gap: 20px;
  margin-bottom: 20px;
}

.function-card {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.card-header {
  background-color: #f8fafc;
  padding: 15px 20px;
  border-bottom: 1px solid #e2e8f0;
}

.card-header h2 {
  margin: 0;
  font-size: 18px;
  color: #334155;
}

.card-body {
  padding: 20px;
}

.description {
  margin-top: 0;
  margin-bottom: 20px;
  color: #64748b;
  line-height: 1.6;
}

.function-btn {
  background-color: #3b82f6;
  color: white;
  border: none;
  border-radius: 4px;
  padding: 10px 20px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: background-color 0.2s;
  margin-top: 10px;
}

.function-btn:hover:not(:disabled) {
  background-color: #2563eb;
}

.input-group {
  margin-bottom: 15px;
}

.input-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #334155;
}

.input-group input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 14px;
}

.input-group input:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.log-card {
  max-height: 400px;
  display: flex;
  flex-direction: column;
}

.log-card .card-body {
  flex: 1;
  overflow-y: auto;
  padding: 0;
}

.log-entries {
  list-style: none;
  margin: 0;
  padding: 0;
}

.log-entries li {
  padding: 10px 20px;
  border-bottom: 1px solid #f1f5f9;
  font-family: monospace;
  font-size: 14px;
  white-space: pre-wrap;
  word-break: break-all;
}

.log-entries li:last-child {
  border-bottom: none;
}

.empty-log {
  padding: 20px;
  text-align: center;
  color: #94a3b8;
  font-style: italic;
}

@media (max-width: 768px) {
  .card-container {
    flex-direction: column;
  }
}
</style> 