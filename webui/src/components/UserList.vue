<script setup>
import { ref, onMounted, computed } from 'vue'
import API_CONFIG from '../utils/config.js'

const users = ref([])
const loading = ref(true)
const error = ref(null)
const lastUpdated = ref('')
const showCertModal = ref(false)
const selectedCert = ref(null)
const certLoading = ref(false)
const certError = ref(null)
const searchQuery = ref('')
const apiUrl = API_CONFIG.BASE_URL

// 分页相关
const currentPage = ref(1)
const itemsPerPage = 10

// 过滤用户列表
const filteredUsers = computed(() => {
  if (!searchQuery.value) return users.value
  
  const query = searchQuery.value.toLowerCase()
  return users.value.filter(user => {
    return user.id.toLowerCase().includes(query) || 
           user.certHash.toLowerCase().includes(query)
  })
})

// 计算总页数
const totalPages = computed(() => {
  return Math.ceil(filteredUsers.value.length / itemsPerPage)
})

// 计算当前页面显示的数据
const paginatedUsers = computed(() => {
  const startIndex = (currentPage.value - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  return filteredUsers.value.slice(startIndex, endIndex)
})

// 页面切换函数
const goToPage = (page) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
  }
}

// 格式化日期时间
function formatDateTime(date) {
  const options = { 
    year: 'numeric', 
    month: '2-digit', 
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }
  return new Date(date).toLocaleString('zh-CN', options)
}

// 格式化时间戳
function formatTimestamp(timestamp) {
  const date = new Date(timestamp * 1000)
  return formatDateTime(date)
}

// 简单的加载提示
function showLoadingToast(message) {
  // 这里仅用console.log记录，可以根据实际UI框架替换成真正的loading提示
  console.log(message);
  return {
    // 返回一个对象，可以包含关闭方法等
    close: () => console.log('加载完成')
  };
}

// 获取用户列表数据
async function fetchUserList() {
  try {
    loading.value = true
    error.value = null
    
    const response = await fetch(`${apiUrl}/api/users`)
    
    if (!response.ok) {
      throw new Error(`获取用户列表失败: ${response.status}`)
    }
    
    users.value = await response.json()
    lastUpdated.value = formatDateTime(new Date())
    // 重置为第一页
    currentPage.value = 1
  } catch (err) {
    error.value = err.message
    console.error('获取用户列表错误:', err)
  } finally {
    loading.value = false
  }
}

// 手动刷新数据
function refreshData() {
  fetchUserList()
}

// 清除搜索
function clearSearch() {
  searchQuery.value = ''
  // 重置为第一页
  currentPage.value = 1
}

// 查看用户证书
async function viewCertificate(userId) {
  try {
    certLoading.value = true
    certError.value = null
    showCertModal.value = true
    selectedCert.value = null
    
    const response = await fetch(`${apiUrl}/api/users/certificate?userId=${encodeURIComponent(userId)}`)
    
    if (!response.ok) {
      throw new Error(`获取证书失败: ${response.status}`)
    }
    
    selectedCert.value = await response.json()
  } catch (err) {
    certError.value = err.message
    console.error('获取证书错误:', err)
  } finally {
    certLoading.value = false
  }
}

// 撤销证书（暂未实现功能）
function revokeCertificate(userId) {
  const confirmRevoke = confirm(`确定要撤销用户 ${userId} 的证书吗？此操作不可撤销。`);
  if (!confirmRevoke) return;
  
  const loadingToast = showLoadingToast('正在撤销证书...');
  
  fetch(`${apiUrl}/api/revoke-certificate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ userId })
  })
  .then(response => {
    if (!response.ok) {
      throw new Error(`撤销证书失败: ${response.status}`);
    }
    return response.json();
  })
  .then(data => {
    if (data.success) {
      alert('证书撤销成功');
      // 刷新用户列表
      fetchUserList();
    } else {
      alert(`撤销失败: ${data.message || '未知错误'}`);
    }
  })
  .catch(err => {
    console.error('撤销证书错误:', err);
    alert(`撤销证书失败: ${err.message}`);
  })
  .finally(() => {
    // 如果有loading提示，可以在这里关闭
    // 暂时简单alert实现
  });
}

// 关闭证书弹窗
function closeCertModal() {
  showCertModal.value = false
  selectedCert.value = null
}

onMounted(() => {
  fetchUserList()
})
</script>

<template>
  <div class="user-list">
    <div class="header">
      <h1>用户列表</h1>
      <div class="right-actions">
        <button @click="refreshData" :disabled="loading" class="refresh-btn">
          <span v-if="loading">刷新中...</span>
          <span v-else>刷新数据</span>
        </button>
        <div v-if="lastUpdated" class="last-updated">
          最后更新: {{ lastUpdated }}
        </div>
      </div>
    </div>
    
    <div class="search-container">
      <div class="search-box">
        <input 
          type="text" 
          v-model="searchQuery" 
          placeholder="搜索用户ID或证书哈希值..." 
          class="search-input"
        />
        <button v-if="searchQuery" @click="clearSearch" class="clear-btn">×</button>
      </div>
    </div>
    
    <div v-if="loading && users.length === 0" class="loading">
      加载中...
    </div>
    
    <div v-else-if="error" class="error">
      <p>加载失败: {{ error }}</p>
      <p>请确保CA Web服务已启动并运行在端口8888上</p>
    </div>
    
    <div v-else-if="users.length === 0" class="empty-state">
      当前没有用户数据可显示
    </div>
    
    <div v-else-if="filteredUsers.length === 0" class="empty-state">
      没有匹配的搜索结果 <a href="#" @click.prevent="clearSearch">清除搜索</a>
    </div>
    
    <div v-else class="user-data-container">
      <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>用户ID</th>
            <th>证书哈希值</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
            <tr v-for="user in paginatedUsers" :key="user.id">
            <td>{{ user.id }}</td>
            <td class="hash-value-cell">
              <div class="hash-value">{{ user.certHash }}</div>
            </td>
            <td class="actions-cell">
              <button @click="viewCertificate(user.id)" class="view-cert-btn">查看证书</button>
              <button @click="revokeCertificate(user.id)" class="revoke-cert-btn">撤销证书</button>
            </td>
          </tr>
        </tbody>
      </table>
      </div>
      
      <!-- 分页控件 -->
      <div v-if="totalPages > 1" class="pagination">
        <button 
          class="page-btn" 
          :disabled="currentPage === 1" 
          @click="goToPage(currentPage - 1)"
        >
          上一页
        </button>
        
        <div class="page-info">
          {{ currentPage }} / {{ totalPages }} 页
        </div>
        
        <button 
          class="page-btn" 
          :disabled="currentPage === totalPages" 
          @click="goToPage(currentPage + 1)"
        >
          下一页
        </button>
      </div>
    </div>
    
    <!-- 证书查看弹窗 -->
    <div v-if="showCertModal" class="modal-overlay" @click="closeCertModal">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h2>证书信息</h2>
          <button class="close-btn" @click="closeCertModal">&times;</button>
        </div>
        
        <div v-if="certLoading" class="modal-loading">
          加载证书信息中...
        </div>
        
        <div v-else-if="certError" class="modal-error">
          获取证书失败: {{ certError }}
        </div>
        
        <div v-else-if="selectedCert" class="cert-details">
          <div class="cert-field">
            <div class="cert-label">序列号</div>
            <div class="cert-value">{{ selectedCert.serialNum }}</div>
          </div>
          
          <div class="cert-field">
            <div class="cert-label">颁发者</div>
            <div class="cert-value">{{ selectedCert.issuerID }}</div>
          </div>
          
          <div class="cert-field">
            <div class="cert-label">主体ID</div>
            <div class="cert-value">{{ selectedCert.subjectID }}</div>
          </div>
          
          <div class="cert-field">
            <div class="cert-label">生效时间</div>
            <div class="cert-value">{{ formatTimestamp(selectedCert.validFrom) }}</div>
          </div>
          
          <div class="cert-field">
            <div class="cert-label">过期时间</div>
            <div class="cert-value">{{ formatTimestamp(selectedCert.validTo) }}</div>
          </div>
          
          <div class="cert-field">
            <div class="cert-label">证书哈希值</div>
            <div class="cert-value cert-hash">{{ selectedCert.certHash }}</div>
          </div>
          
          <div class="cert-field">
            <div class="cert-label">部分公钥信息</div>
            <div class="cert-value cert-pubkey">{{ selectedCert.pubKey }}</div>
          </div>

          <div class="cert-status" :class="selectedCert.isValid ? 'valid' : 'invalid'">
            <div class="status-indicator"></div>
            {{ selectedCert.isValid ? '证书有效' : (selectedCert.isRevoked ? '证书已被撤销' : '证书已过期') }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* 添加分页样式 */
.user-data-container {
  display: flex;
  flex-direction: column;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 16px 0;
  margin-top: 10px;
  border-top: 1px solid #e5e7eb;
}

.page-btn {
  background-color: #f1f5f9;
  border: none;
  color: #334155;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.page-btn:hover:not(:disabled) {
  background-color: #e2e8f0;
}

.page-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-info {
  margin: 0 16px;
  color: #475569;
  font-size: 14px;
}

/* 保留原有的样式 */
.user-list {
  padding: 20px;
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

h1 {
  font-size: 24px;
  color: #334155;
  margin: 0;
}

.right-actions {
  display: flex;
  align-items: center;
}

.refresh-btn {
  background-color: #3b82f6;
  border: none;
  color: white;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.refresh-btn:hover {
  background-color: #2563eb;
}

.refresh-btn:disabled {
  background-color: #93c5fd;
  opacity: 0.7;
  cursor: not-allowed;
}

.last-updated {
  margin-left: 16px;
  font-size: 14px;
  color: #64748b;
}

.search-container {
  margin-bottom: 20px;
}

.search-box {
  position: relative;
  max-width: 500px;
}

.search-input {
  width: 100%;
  padding: 10px 16px;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  font-size: 16px;
  color: #334155;
}

.search-input:focus {
  outline: none;
  border-color: #94a3b8;
  box-shadow: 0 0 0 2px rgba(148, 163, 184, 0.1);
}

.clear-btn {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  font-size: 18px;
  color: #94a3b8;
  cursor: pointer;
}

.clear-btn:hover {
  color: #64748b;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 12px;
  border-bottom: 2px solid #e2e8f0;
  font-weight: 600;
  color: #475569;
}

td {
  padding: 12px;
  border-bottom: 1px solid #e2e8f0;
}

.hash-value-cell {
  max-width: 300px;
}

.hash-value {
  word-break: break-all;
  font-family: 'Courier New', monospace;
  font-size: 14px;
  color: #334155;
}

.actions-cell {
  white-space: nowrap;
}

.view-cert-btn, .revoke-cert-btn {
  padding: 6px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  margin-right: 8px;
}

.view-cert-btn {
  background-color: #e0f2fe;
  color: #0369a1;
}

.view-cert-btn:hover {
  background-color: #bae6fd;
}

.revoke-cert-btn {
  background-color: #fee2e2;
  color: #b91c1c;
}

.revoke-cert-btn:hover {
  background-color: #fecaca;
}

.loading, .empty-state {
  text-align: center;
  padding: 40px 0;
  color: #64748b;
}

.error {
  text-align: center;
  padding: 40px 0;
  color: #ef4444;
}

/* 弹窗样式 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background-color: white;
  border-radius: 8px;
  width: 90%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
  border-bottom: 1px solid #e2e8f0;
}

.modal-header h2 {
  margin: 0;
  font-size: 20px;
  color: #334155;
}

.close-btn {
  background: none;
  border: none;
  font-size: 24px;
  color: #64748b;
  cursor: pointer;
}

.close-btn:hover {
  color: #334155;
}

.modal-loading, .modal-error {
  padding: 40px 24px;
  text-align: center;
  color: #64748b;
}

.modal-error {
  color: #ef4444;
}

.cert-details {
  padding: 24px;
  overflow-y: auto;
}

.cert-field {
  margin-bottom: 16px;
}

.cert-label {
  font-weight: 600;
  color: #475569;
  margin-bottom: 4px;
}

.cert-value {
  padding: 8px 12px;
  background-color: #f8fafc;
  border-radius: 4px;
  border: 1px solid #e2e8f0;
  word-break: break-all;
}

.cert-pubkey, .cert-hash {
  font-family: 'Courier New', monospace;
  font-size: 14px;
  color: #334155;
  background-color: #f8fafc;
  padding: 8px;
  border-radius: 4px;
  overflow-x: auto;
}

.cert-status {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 12px;
  margin-top: 16px;
  border-radius: 4px;
  font-weight: 600;
}

.status-indicator {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 8px;
}

.valid {
  background-color: #dcfce7;
  color: #166534;
}

.valid .status-indicator {
  background-color: #10b981;
}

.invalid {
  background-color: #fee2e2;
  color: #b91c1c;
}

.invalid .status-indicator {
  background-color: #ef4444;
}
</style> 