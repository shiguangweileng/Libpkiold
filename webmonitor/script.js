// 全局变量
let userData = [];
let crlData = [];
let userSearchTerm = '';
let crlSearchTerm = '';
let isFirstLoad = true;

// 常量
const REFRESH_INTERVAL = 3000; // 3秒刷新一次数据
const EXPIRE_CHECK_INTERVAL = 30000; // 30秒检查一次过期证书

// DOM 元素
const userTableBody = document.getElementById('user-list');
const crlTableBody = document.getElementById('crl-list');
const userSearch = document.getElementById('user-search');
const crlSearch = document.getElementById('crl-search');
const lastUpdateElement = document.getElementById('last-update');
const userCountElement = document.getElementById('user-count');
const revokedCountElement = document.getElementById('revoked-count');
const syncIcon = document.getElementById('sync-icon');
const modal = document.getElementById('cert-modal');
const closeBtn = document.querySelector('.close');
const certDetails = document.getElementById('cert-details');
const cleanCrlBtn = document.getElementById('clean-crl-btn');

// 初始化页面
function init() {
    // 加载初始数据
    fetchData();
    
    // 设置定时刷新
    setInterval(fetchData, REFRESH_INTERVAL);
    
    // 设置定时检查过期证书 - 确保每30秒检查一次
    setInterval(checkExpiredCerts, EXPIRE_CHECK_INTERVAL);
    
    // 搜索事件监听
    userSearch.addEventListener('input', function() {
        userSearchTerm = this.value.trim().toLowerCase();
        renderUserTable();
    });
    
    crlSearch.addEventListener('input', function() {
        crlSearchTerm = this.value.trim().toLowerCase();
        renderCrlTable();
    });

    // 清理CRL按钮事件监听
    cleanCrlBtn.addEventListener('click', function() {
        cleanExpiredCerts();
    });

    // 关闭模态对话框
    closeBtn.addEventListener('click', function() {
        modal.style.display = 'none';
    });
    
    // 点击模态对话框外部关闭
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

// 检查过期证书并更新UI
function checkExpiredCerts() {
    if (crlData.length === 0) return;
    
    const currentTime = Math.floor(Date.now() / 1000); // 当前时间的Unix时间戳
    let hasExpired = false;
    
    // 检查所有CRL数据，标记已过期的证书
    crlData.forEach(cert => {
        // 确保expire_time是数字
        const expireTime = parseInt(cert.expire_time, 10);
        
        // 检查是否过期
        if (expireTime && expireTime < currentTime) {
            cert.isExpired = true;
            hasExpired = true;
            console.log("证书已过期:", cert.id, "过期时间:", new Date(expireTime * 1000).toLocaleString());
        } else {
            // 保持现有状态不变，如果之前已标记为过期，则保持过期状态
            if (!cert.hasOwnProperty('isExpired')) {
                cert.isExpired = false;
            }
        }
    });
    
    // 更新CRL表格显示
    renderCrlTable();
    
}

// 获取数据
function fetchData() {
    syncIcon.classList.add('fa-spin');
    
    // 获取用户列表数据
    fetch('/api/users')
        .then(response => response.json())
        .then(data => {
            // 检查是否有数据更新
            const isDataChanged = JSON.stringify(userData) !== JSON.stringify(data.users);
            userData = data.users || [];
            renderUserTable(isDataChanged);
            userCountElement.textContent = userData.length;
        })
        .catch(error => {
            console.error('获取用户数据失败:', error);
        });
    
    // 获取CRL数据
    fetch('/api/crl')
        .then(response => response.json())
        .then(data => {
            // 检查是否有数据更新
            const isDataChanged = JSON.stringify(crlData) !== JSON.stringify(data.revoked_certs);
            
            // 保留之前的过期状态标记
            if (crlData.length > 0 && data.revoked_certs) {
                data.revoked_certs.forEach(newCert => {
                    const existingCert = crlData.find(cert => cert.hash === newCert.hash);
                    if (existingCert && existingCert.isExpired) {
                        newCert.isExpired = true;
                    }
                });
            }
            
            crlData = data.revoked_certs || [];
            renderCrlTable(isDataChanged);
            revokedCountElement.textContent = crlData.length;
            
            // 获取新数据后检查过期状态
            checkExpiredCerts();
        })
        .catch(error => {
            console.error('获取CRL数据失败:', error);
        })
        .finally(() => {
            // 更新最后刷新时间
            const now = new Date();
            lastUpdateElement.textContent = `最后更新: ${formatDate(now)}`;
            syncIcon.classList.remove('fa-spin');
            isFirstLoad = false;
        });
}

// 渲染用户表格
function renderUserTable(isDataChanged = false) {
    // 清空表格
    userTableBody.innerHTML = '';
    
    // 过滤用户数据
    const filteredUsers = userData.filter(user => 
        user.id.toLowerCase().includes(userSearchTerm) || 
        user.hash.toLowerCase().includes(userSearchTerm)
    );
    
    // 如果没有用户数据，显示提示信息
    if (filteredUsers.length === 0) {
        userTableBody.innerHTML = `
            <tr>
                <td colspan="3" class="empty-message">
                    <i class="fas fa-info-circle"></i> 没有找到匹配的用户数据
                </td>
            </tr>
        `;
        return;
    }
    
    // 创建表格行
    filteredUsers.forEach(user => {
        const row = document.createElement('tr');
        if (isDataChanged && !isFirstLoad) row.classList.add('highlight');
        
        // 使用带工具提示的哈希值显示
        row.innerHTML = `
            <td>${user.id}</td>
            <td class="hash-value">${user.hash}</td>
            <td>
                <button class="btn btn-view" onclick="viewCert('${user.id}')">
                    查看证书
                </button>
            </td>
        `;
        
        // 添加行到表格
        userTableBody.appendChild(row);
    });
}

// 渲染CRL表格
function renderCrlTable(isDataChanged = false) {
    // 清空表格
    crlTableBody.innerHTML = '';
    
    // 过滤CRL数据
    const filteredCRL = crlData.filter(cert => 
        cert.hash.toLowerCase().includes(crlSearchTerm)
    );
    
    // 如果没有CRL数据，显示提示信息
    if (filteredCRL.length === 0) {
        crlTableBody.innerHTML = `
            <tr>
                <td colspan="2" class="empty-message">
                    <i class="fas fa-info-circle"></i> 没有找到匹配的CRL数据
                </td>
            </tr>
        `;
        return;
    }
    
    // 创建表格行
    filteredCRL.forEach(cert => {
        const row = document.createElement('tr');
        if (isDataChanged && !isFirstLoad) row.classList.add('highlight');
        
        // 根据证书过期状态应用不同样式
        const hashClass = cert.isExpired ? 'hash-value expired' : 'hash-value';
        
        row.innerHTML = `
            <td>${cert.id}</td>
            <td class="${hashClass}" data-expire="${cert.expire_time}">${cert.hash}</td>
        `;
        
        crlTableBody.appendChild(row);
    });
}

// 格式化日期
function formatDate(date) {
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// 格式化哈希值 - 移除空格格式化，以便显示完整哈希值
function formatHash(hash) {
    // 确保hash是字符串并且非空
    if (!hash || typeof hash !== 'string') return '';
    // 直接返回原始哈希值，不再添加空格
    return hash;
}

// 查看证书函数 - 必须在全局范围内定义，因为它是通过onclick调用的
function viewCert(userId) {
    const modal = document.getElementById('cert-modal');
    const certDetails = document.getElementById('cert-details');
    
    // 显示模态对话框
    modal.style.display = 'block';
    certDetails.innerHTML = '<div class="loader">正在加载证书信息...</div>';
    
    // 请求证书信息
    fetch(`/api/cert?id=${userId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('证书获取失败');
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                certDetails.innerHTML = `<div class="cert-error">${data.error}</div>`;
                return;
            }
            
            // 格式化时间
            const startDate = new Date(data.start_time * 1000).toLocaleString();
            const endDate = new Date(data.end_time * 1000).toLocaleString();
            
            // 构建证书信息HTML
            certDetails.innerHTML = `
                <div class="cert-info-item">
                    <span class="cert-info-label">序列号:</span>
                    <span class="cert-info-value">${data.serial_num}</span>
                </div>
                <div class="cert-info-item">
                    <span class="cert-info-label">颁发者:</span>
                    <span class="cert-info-value">${data.issuer_id}</span>
                </div>
                <div class="cert-info-item">
                    <span class="cert-info-label">主体ID:</span>
                    <span class="cert-info-value">${data.subject_id}</span>
                </div>
                <div class="cert-info-item cert-validity">
                    <div class="cert-validity-item">
                        <span class="cert-info-label">生效时间:</span>
                        <span class="cert-info-value">${startDate}</span>
                    </div>
                    <div class="cert-validity-item">
                        <span class="cert-info-label">到期时间:</span>
                        <span class="cert-info-value">${endDate}</span>
                    </div>
                </div>
                <div class="cert-info-item">
                    <span class="cert-info-label">部分公钥:</span>
                    <span class="cert-info-value">${data.pub_key}</span>
                </div>
            `;
        })
        .catch(error => {
            certDetails.innerHTML = `<div class="cert-error">错误: ${error.message}</div>`;
        });
}

// 清理过期证书
function cleanExpiredCerts() {
    cleanCrlBtn.disabled = true;
    cleanCrlBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 清理中...';
    
    fetch('/api/clean-crl', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // 清理成功，刷新数据
            fetchData();
            
            // 显示清理结果
            const message = `清理成功，已删除 ${data.cleaned_count} 个过期证书`;
            showNotification(message, 'success');
        } else {
            showNotification('清理失败: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('清理CRL时出错:', error);
        showNotification('清理过程中发生错误', 'error');
    })
    .finally(() => {
        cleanCrlBtn.disabled = false;
        cleanCrlBtn.innerHTML = '<i class="fas fa-broom"></i> 定期清理';
    });
}

// 显示通知消息
function showNotification(message, type = 'info') {
    // 如果页面上没有通知容器，创建一个
    let notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        document.body.appendChild(notificationContainer);
    }
    
    // 创建通知元素
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="close-notification">&times;</button>
    `;
    
    // 添加到容器
    notificationContainer.appendChild(notification);
    
    // 添加关闭按钮事件
    notification.querySelector('.close-notification').addEventListener('click', function() {
        notification.remove();
    });
    
    // 3秒后自动关闭
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => notification.remove(), 500);
    }, 3000);
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', init);
