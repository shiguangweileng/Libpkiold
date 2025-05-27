<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  visible: {
    type: Boolean,
    default: false
  },
  title: {
    type: String,
    default: '提示'
  },
  message: {
    type: String,
    default: ''
  },
  type: {
    type: String,
    default: 'alert', // 'alert' 或 'confirm'
  },
  confirmText: {
    type: String,
    default: '确定'
  },
  cancelText: {
    type: String,
    default: '取消'
  }
})

const emit = defineEmits(['confirm', 'cancel', 'update:visible'])

// 确认按钮点击
const handleConfirm = () => {
  emit('confirm')
  emit('update:visible', false)
}

// 取消按钮点击
const handleCancel = () => {
  emit('cancel')
  emit('update:visible', false)
}

// 关闭对话框
const close = () => {
  emit('update:visible', false)
}

// 监听ESC键关闭对话框
const handleKeydown = (e) => {
  if (e.key === 'Escape' && props.visible) {
    close()
  }
}

// 添加和移除ESC键监听
watch(() => props.visible, (newValue) => {
  if (newValue) {
    document.addEventListener('keydown', handleKeydown)
  } else {
    document.removeEventListener('keydown', handleKeydown)
  }
})
</script>

<template>
  <Teleport to="body">
    <div v-if="visible" class="dialog-overlay" @click="close">
      <div class="dialog-container" @click.stop>
        <div class="dialog-header">
          <h3>{{ title }}</h3>
          <button class="close-button" @click="close">×</button>
        </div>
        <div class="dialog-content">
          <p>{{ message }}</p>
        </div>
        <div class="dialog-footer">
          <button v-if="type === 'confirm'" class="cancel-button" @click="handleCancel">
            {{ cancelText }}
          </button>
          <button class="confirm-button" @click="handleConfirm">
            {{ confirmText }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 999;
}

.dialog-container {
  background-color: white;
  border-radius: 8px;
  width: 400px;
  max-width: 90%;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
  animation: dialog-fade-in 0.3s ease;
}

.dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  border-bottom: 1px solid #e2e8f0;
}

.dialog-header h3 {
  margin: 0;
  font-size: 1.2rem;
  color: #1e293b;
}

.close-button {
  background: none;
  border: none;
  font-size: 1.5rem;
  color: #64748b;
  cursor: pointer;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
}

.close-button:hover {
  color: #334155;
}

.dialog-content {
  padding: 20px;
  font-size: 1rem;
  color: #334155;
}

.dialog-content p {
  margin: 0;
}

.dialog-footer {
  padding: 16px 20px;
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  border-top: 1px solid #e2e8f0;
}

.cancel-button {
  padding: 8px 16px;
  border: 1px solid #e2e8f0;
  background-color: white;
  color: #64748b;
  border-radius: 4px;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s;
}

.cancel-button:hover {
  background-color: #f1f5f9;
  color: #334155;
}

.confirm-button {
  padding: 8px 16px;
  border: none;
  background-color: #3b82f6;
  color: white;
  border-radius: 4px;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s;
}

.confirm-button:hover {
  background-color: #2563eb;
}

@keyframes dialog-fade-in {
  from {
    opacity: 0;
    transform: translateY(-20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style> 