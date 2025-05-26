<script setup>
import { ref } from 'vue'
import API_CONFIG from '../utils/config.js'

const apiUrl = API_CONFIG.BASE_URL
// 发件箱相关数据
const userId = ref('U0000001')
const privateKey = ref('')
const publicKey = ref('')
const messageToSend = ref('')
const sendLogs = ref([])

// 收件箱相关数据
const receivedMessage = ref('')
const messageSignature = ref('')
const reconstructedPublicKey = ref('')
const verificationLogs = ref([])
const verificationResult = ref(false)
const hasVerified = ref(false) // 追踪是否已进行验证

// 记录发送日志
function logSendAction(message) {
  const timestamp = new Date().toLocaleString('zh-CN')
  sendLogs.value.unshift(`[${timestamp}] ${message}`)
}

// 记录验证日志
function logVerifyAction(message) {
  const timestamp = new Date().toLocaleString('zh-CN')
  verificationLogs.value.unshift(`[${timestamp}] ${message}`)
}

// 读取用户公私钥对
async function loadKeyPair() {
  if (!userId.value) {
    logSendAction('错误：用户ID不能为空')
    return
  }
  
  logSendAction(`尝试读取用户 ${userId.value} 的公私钥对`)
  
  try {
    // 使用新的API接口和GET参数方式获取密钥对
    const response = await fetch(`${apiUrl}/api/keypair?userId=${userId.value}`)
    
    if (!response.ok) {
      throw new Error(`HTTP错误: ${response.status}`)
    }
    
    const data = await response.json()
    
    if (data.success) {
      privateKey.value = data.privateKey
      publicKey.value = data.publicKey
      logSendAction('成功读取公私钥对')
    } else {
      logSendAction(`错误：${data.message || '读取公私钥对失败'}`)
    }
  } catch (error) {
    logSendAction(`错误：${error.message}`)
  }
}

// 发送消息功能（使用私钥签名）
async function sendMessage() {
  if (!userId.value) {
    logSendAction('错误：用户ID不能为空')
    return
  }
  if (!privateKey.value) {
    logSendAction('错误：私钥不能为空')
    return
  }
  if (!messageToSend.value) {
    logSendAction('错误：消息内容不能为空')
    return
  }
  
  logSendAction(`尝试发送用户 ${userId.value} 的消息`)
  
  try {
    const response = await fetch(`${apiUrl}/api/sign-message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId: userId.value,
        privateKey: privateKey.value,
        message: messageToSend.value
      })
    })
    
    if (!response.ok) {
      throw new Error(`HTTP错误: ${response.status}`)
    }
    
    const data = await response.json()
    
    if (data.success) {
      receivedMessage.value = messageToSend.value
      messageSignature.value = data.signature
      logSendAction('消息已发送并签名')
    } else {
      logSendAction(`错误：${data.message || '消息签名失败'}`)
    }
  } catch (error) {
    logSendAction(`错误：${error.message}`)
  }
}

// 验证签名功能
async function verifySignature() {
  if (!receivedMessage.value) {
    logVerifyAction('错误：没有接收到消息')
    return
  }
  if (!messageSignature.value) {
    logVerifyAction('错误：没有消息签名')
    return
  }
  
  logVerifyAction('尝试验证消息签名')
  
  try {
    const response = await fetch(`${apiUrl}/api/verify-signature`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId: userId.value,
        message: receivedMessage.value,
        signature: messageSignature.value
      })
    })
    
    if (!response.ok) {
      throw new Error(`HTTP错误: ${response.status}`)
    }
    
    const data = await response.json()
    
    if (data.success) {
      reconstructedPublicKey.value = data.reconstructedPublicKey
      verificationResult.value = data.verified
      hasVerified.value = true
      logVerifyAction(`签名验证${data.verified ? '成功' : '失败'}`)
    } else {
      hasVerified.value = true
      verificationResult.value = false
      logVerifyAction(`错误：${data.message || '签名验证失败'}`)
    }
  } catch (error) {
    hasVerified.value = true
    verificationResult.value = false
    logVerifyAction(`错误：${error.message}`)
  }
}
</script>

<template>
  <div class="message-center">
    <div class="header">
      <h1>消息中心</h1>
    </div>
    
    <div class="card-container">
      <!-- 模拟用户发送信息卡片 -->
      <div class="card function-card">
        <div class="card-header">
          <h2>模拟用户发送信息</h2>
        </div>
        <div class="card-body">
          <div class="input-group">
            <label for="user-id">用户ID:</label>
            <input 
              id="user-id" 
              v-model="userId" 
              type="text" 
              placeholder="请输入用户ID"
            />
          </div>
          
          <div class="input-group">
            <label for="private-key">私钥:</label>
            <textarea 
              id="private-key" 
              v-model="privateKey" 
              placeholder="请输入您的私钥"
              rows="3"
            ></textarea>
          </div>
          
          <div class="input-group">
            <label for="public-key">公钥:</label>
            <textarea 
              id="public-key" 
              v-model="publicKey" 
              placeholder="这里将显示用户本地的公钥"
              rows="3"
              readonly
            ></textarea>
          </div>
          
          <div class="input-group">
            <label for="message-to-send">消息内容:</label>
            <textarea 
              id="message-to-send" 
              v-model="messageToSend" 
              placeholder="请输入要发送的消息"
              rows="5"
            ></textarea>
          </div>
          
          <div class="button-group">
            <button 
              @click="sendMessage" 
              :disabled="!userId || !privateKey || !messageToSend" 
              class="function-btn"
            >
              发送消息
            </button>
            
            <button 
              @click="loadKeyPair" 
              :disabled="!userId" 
              class="function-btn load-key-btn"
            >
              读取公私钥对
            </button>
          </div>
          
          <div class="log-container">
            <h3>发送日志</h3>
            <div v-if="sendLogs.length === 0" class="empty-log">
              暂无日志
            </div>
            <ul v-else class="log-entries">
              <li v-for="(entry, index) in sendLogs" :key="index">
                {{ entry }}
              </li>
            </ul>
          </div>
        </div>
      </div>
      
      <!-- 收件箱卡片 -->
      <div class="card function-card">
        <div class="card-header">
          <h2>收件箱</h2>
        </div>
        <div class="card-body">
          <div class="input-group">
            <label for="received-message">接收到的消息:</label>
            <textarea 
              id="received-message" 
              v-model="receivedMessage" 
              placeholder="这里将显示接收到的消息"
              rows="5"
            ></textarea>
          </div>
          
          <div class="input-group">
            <label for="message-signature">消息签名:</label>
            <textarea 
              id="message-signature" 
              v-model="messageSignature" 
              placeholder="这里将显示消息的签名"
              rows="3"
            ></textarea>
          </div>
          
          <div class="input-group">
            <label for="reconstructed-public-key">重构出的公钥:</label>
            <textarea 
              id="reconstructed-public-key" 
              v-model="reconstructedPublicKey" 
              placeholder="这里将显示重构出的公钥"
              rows="3"
              readonly
            ></textarea>
          </div>
          
          <button 
            @click="verifySignature" 
            :disabled="!receivedMessage || !messageSignature" 
            class="function-btn verify-btn"
          >
            验证签名
          </button>
          
          <div v-if="hasVerified" class="verification-result" :class="{ success: verificationResult, failure: !verificationResult }">
            签名验证{{ verificationResult ? '成功' : '失败' }}
          </div>
          
          <div class="log-container">
            <h3>验证日志</h3>
            <div v-if="verificationLogs.length === 0" class="empty-log">
              暂无日志
            </div>
            <ul v-else class="log-entries">
              <li v-for="(entry, index) in verificationLogs" :key="index">
                {{ entry }}
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.message-center {
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

h3 {
  font-size: 16px;
  margin: 20px 0 10px 0;
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

.input-group {
  margin-bottom: 15px;
}

.input-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  color: #334155;
}

.input-group input, .input-group textarea {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 14px;
  font-family: inherit;
  resize: vertical;
}

.input-group input:focus, .input-group textarea:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
}

.button-group {
  display: flex;
  gap: 10px;
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

.load-key-btn {
  background-color: #10b981;
}

.load-key-btn:hover:not(:disabled) {
  background-color: #059669;
}

.verify-btn {
  background-color: #8b5cf6;
}

.verify-btn:hover:not(:disabled) {
  background-color: #7c3aed;
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.verification-result {
  margin-top: 10px;
  padding: 10px;
  text-align: center;
  border-radius: 4px;
  font-weight: bold;
}

.verification-result.success {
  background-color: #dcfce7;
  color: #166534;
  border: 1px solid #bbf7d0;
}

.verification-result.failure {
  background-color: #fee2e2;
  color: #991b1b;
  border: 1px solid #fecaca;
}

.log-container {
  margin-top: 20px;
}

.log-entries {
  list-style: none;
  margin: 0;
  padding: 0;
  max-height: 150px;
  overflow-y: auto;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
}

.log-entries li {
  padding: 8px 12px;
  border-bottom: 1px solid #f1f5f9;
  font-family: monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}

.log-entries li:last-child {
  border-bottom: none;
}

.empty-log {
  padding: 12px;
  text-align: center;
  color: #94a3b8;
  font-style: italic;
  font-size: 14px;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
}

@media (max-width: 768px) {
  .card-container {
    flex-direction: column;
  }
}
</style> 