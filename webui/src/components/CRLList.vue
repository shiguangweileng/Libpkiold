<script setup>
import { ref, onMounted, computed } from 'vue'
import { formatDate } from '../utils/formatters'
import API_CONFIG from '../utils/config.js'

const crlData = ref({
  baseVersion: 0,
  removedVersion: 0,
  crlItems: []
})
const loading = ref(true)
const error = ref(null)
const lastUpdated = ref('')
const cleanupLoading = ref(false)
const cleanupResult = ref(null)
const apiUrl = API_CONFIG.BASE_URL

// 分页相关
const currentPage = ref(1)
const itemsPerPage = 10

// 计算总页数
const totalPages = computed(() => {
  return Math.ceil(crlData.value.crlItems.length / itemsPerPage)
})

// 计算当前页面显示的数据
const paginatedCRLList = computed(() => {
  const startIndex = (currentPage.value - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  return crlData.value.crlItems.slice(startIndex, endIndex)
})

// 页面切换函数
const goToPage = (page) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
  }
}

// 获取CRL列表数据
const fetchCRLList = async () => {
  try {
    loading.value = true
    const response = await fetch(`${apiUrl}/api/crl`)
    
    if (!response.ok) {
      throw new Error(`获取证书撤销列表失败: ${response.status}`)
    }
    
    const data = await response.json()
    crlData.value = data
    
    // 更新最后刷新时间
    lastUpdated.value = formatDate(new Date())
    
    // 重置为第一页
    currentPage.value = 1
  } catch (err) {
    error.value = err.message
    console.error('获取证书撤销列表错误:', err)
  } finally {
    loading.value = false
  }
}

// 清理过期证书
const cleanupExpiredCerts = async () => {
  try {
    cleanupLoading.value = true
    cleanupResult.value = null
    
    const response = await fetch(`${apiUrl}/api/cleanup-expired-certs`, {
      method: 'POST'
    })
    
    if (!response.ok) {
      throw new Error(`清理过期证书失败: ${response.status}`)
    }
    
    const data = await response.json()
    cleanupResult.value = {
      success: true,
      message: `成功清理 ${data.cleanedCount} 个过期证书`
    }
    
    // 刷新CRL列表
    fetchCRLList()
  } catch (err) {
    cleanupResult.value = {
      success: false,
      message: err.message
    }
    console.error('清理过期证书错误:', err)
  } finally {
    cleanupLoading.value = false
  }
}

// 刷新CRL列表
const refreshCRLList = () => {
  fetchCRLList()
}

onMounted(() => {
  fetchCRLList()
})
</script>

<template>
  <div class="crl-list">
    <div class="header-section">
      <h1>证书撤销列表 (CRL)</h1>
      <div class="right-actions">
        <button @click="refreshCRLList" class="refresh-btn" :disabled="loading">
          <span v-if="!loading">刷新数据</span>
          <span v-else>加载中...</span>
        </button>
        <div v-if="lastUpdated" class="last-updated">
          最后更新: {{ lastUpdated }}
        </div>
      </div>
    </div>
    
    <!-- 版本信息区域 -->
    <div v-if="!loading && !error" class="version-info">
      <div class="version-info-left">
        <div class="version-badge">
          base_v: <span class="version-number">{{ crlData.baseVersion }}</span>
        </div>
        <div class="version-badge">
          removed_v: <span class="version-number">{{ crlData.removedVersion }}</span>
        </div>
        <div class="version-badge">
          已撤销: <span class="version-number revoked-number">{{ crlData.crlItems.length }}</span>
        </div>
      </div>
      <div class="version-info-right">
        <button 
          class="cleanup-btn" 
          @click="cleanupExpiredCerts"
          :disabled="cleanupLoading"
        >
          {{ cleanupLoading ? '正在清理...' : '清理过期证书' }}
        </button>
      </div>
    </div>
    
    <!-- 清理结果提示 -->
    <div v-if="cleanupResult" :class="['cleanup-result', cleanupResult.success ? 'success' : 'error']">
      {{ cleanupResult.message }}
    </div>
    
    <div v-if="loading" class="loading">
      <div class="spinner"></div>
      <p>正在获取最新撤销列表...</p>
    </div>
    
    <div v-else-if="error" class="error">
      <p>加载失败: {{ error }}</p>
      <p>请确保CA Web服务已启动并运行在端口8888上</p>
    </div>
    
    <div v-else-if="crlData.crlItems.length === 0" class="empty-state">
      <div class="empty-icon">📋</div>
      <p>当前没有已撤销的证书</p>
    </div>
    
    <div v-else class="crl-data-container">
      <div class="crl-table-container">
      <table>
        <thead>
          <tr>
              <th>证书哈希</th>
              <th>到期时间</th>
          </tr>
        </thead>
        <tbody>
            <tr v-for="(crl, index) in paginatedCRLList" :key="index">
              <td class="hash-cell">
                <div class="hash-display">{{ crl.certHash }}</div>
              </td>
              <td>{{ formatDate(crl.expireTime) }}</td>
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
  </div>
</template>

<style scoped>
.crl-list {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
  padding: 24px;
  height: 100%;
  display: flex;
  flex-direction: column;
}

.header-section {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.right-actions {
  display: flex;
  align-items: center;
}

.last-updated {
  margin-left: 16px;
  font-size: 14px;
  color: #64748b;
}

h1 {
  font-size: 24px;
  margin: 0;
  color: #334155;
}

/* 版本信息样式 */
.version-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding: 12px 16px;
  background-color: #f8fafc;
  border-radius: 6px;
  border-left: 3px solid #0ea5e9;
}

.version-info-left {
  display: flex;
  gap: 16px;
}

.version-info-right {
  margin-left: auto;
}

.version-badge {
  display: flex;
  align-items: center;
  font-size: 14px;
  color: #475569;
}

.version-number {
  display: inline-block;
  background-color: #e0f2fe;
  color: #0369a1;
  font-weight: 600;
  padding: 2px 8px;
  margin-left: 4px;
  border-radius: 4px;
}

.revoked-number {
  background-color: #fee2e2;
  color: #b91c1c;
}

.cleanup-btn {
  background-color: #dcfce7;
  color: #166534;
  border: 1px solid #86efac;
  padding: 8px 16px;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.cleanup-btn:hover:not(:disabled) {
  background-color: #bbf7d0;
}

.cleanup-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.cleanup-result {
  margin-bottom: 16px;
  padding: 12px 16px;
  border-radius: 6px;
  font-size: 14px;
  animation: fadeIn 0.3s ease-in-out;
}

.cleanup-result.success {
  background-color: #dcfce7;
  color: #166534;
  border: 1px solid #86efac;
}

.cleanup-result.error {
  background-color: #fee2e2;
  color: #b91c1c;
  border: 1px solid #fca5a5;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
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

.crl-data-container {
  display: flex;
  flex-direction: column;
  flex-grow: 1;
}

.crl-table-container {
  overflow-x: auto;
  flex-grow: 1;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 14px 16px;
  text-align: left;
  border-bottom: 1px solid #e2e8f0;
}

th {
  background-color: #f8fafc;
  font-weight: 600;
  color: #475569;
  position: sticky;
  top: 0;
}

tr:hover {
  background-color: #f8fafc;
}

.hash-cell {
  display: flex;
  align-items: center;
}

.hash-display {
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', 'Helvetica Neue', Arial, sans-serif;
  color: #334155;
  word-break: break-all;
  font-size: 14px;
  letter-spacing: 0.2px;
}

.loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  flex-grow: 1;
  padding: 40px;
  color: #64748b;
}

.spinner {
  border: 4px solid rgba(0, 0, 0, 0.1);
  border-radius: 50%;
  border-top: 4px solid #3b82f6;
  width: 36px;
  height: 36px;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.error {
  padding: 30px;
  text-align: center;
  color: #ef4444;
  background-color: #fef2f2;
  border-radius: 6px;
  margin-top: 20px;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  flex-grow: 1;
  padding: 40px;
  color: #64748b;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 16px;
}

/* 分页样式 */
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
</style> 