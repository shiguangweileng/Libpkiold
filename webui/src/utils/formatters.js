/**
 * 日期格式化工具函数
 */

/**
 * 将时间戳或日期字符串格式化为本地日期时间格式
 * @param {number|string|Date} date - 时间戳、日期字符串或Date对象
 * @param {boolean} includeTime - 是否包含时间部分
 * @returns {string} 格式化后的日期时间字符串
 */
export function formatDate(date, includeTime = true) {
  if (!date) return '';
  
  const dateObj = typeof date === 'object' ? date : new Date(date);
  
  if (isNaN(dateObj.getTime())) {
    return date; // 如果无法解析，返回原始值
  }
  
  const options = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  };
  
  if (includeTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
    options.second = '2-digit';
  }
  
  return dateObj.toLocaleString('zh-CN', options);
}

/**
 * 格式化相对时间（例如"3小时前"）
 * @param {number|string|Date} date - 时间戳、日期字符串或Date对象 
 * @returns {string} 相对时间字符串
 */
export function formatRelativeTime(date) {
  if (!date) return '';
  
  const dateObj = typeof date === 'object' ? date : new Date(date);
  
  if (isNaN(dateObj.getTime())) {
    return date; // 如果无法解析，返回原始值
  }
  
  const now = new Date();
  const diffSeconds = Math.floor((now - dateObj) / 1000);
  
  if (diffSeconds < 60) {
    return `${diffSeconds}秒前`;
  }
  
  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) {
    return `${diffMinutes}分钟前`;
  }
  
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours}小时前`;
  }
  
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) {
    return `${diffDays}天前`;
  }
  
  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths < 12) {
    return `${diffMonths}个月前`;
  }
  
  const diffYears = Math.floor(diffMonths / 12);
  return `${diffYears}年前`;
}

/**
 * 格式化文件大小
 * @param {number} bytes - 文件大小（字节）
 * @returns {string} 格式化后的文件大小
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  
  return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
} 