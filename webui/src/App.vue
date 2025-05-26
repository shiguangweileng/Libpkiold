<script setup>
import { ref } from 'vue'
import UserList from './components/UserList.vue'
import CRLList from './components/CRLList.vue'
import LocalMode from './components/LocalMode.vue'
import MessageCenter from './components/MessageCenter.vue'

const activeMenu = ref('users')

const menuItems = [
  { id: 'users', name: '用户列表' },
  { id: 'crl', name: '证书撤销列表' },
  { id: 'localmode', name: '本地模式' },
  { id: 'message', name: '消息中心' }
]
</script>

<template>
  <div class="ca-admin">
    <div class="sidebar">
      <div class="logo">
        <h2>CA管理系统</h2>
      </div>
      <ul class="menu">
        <li v-for="item in menuItems" :key="item.id" 
            :class="{ active: activeMenu === item.id }"
            @click="activeMenu = item.id">
          {{ item.name }}
        </li>
      </ul>
    </div>
    <div class="content">
      <UserList v-if="activeMenu === 'users'" />
      <CRLList v-if="activeMenu === 'crl'" />
      <LocalMode v-if="activeMenu === 'localmode'" />
      <MessageCenter v-if="activeMenu === 'message'" />
    </div>
  </div>
</template>

<style>
body {
  margin: 0;
  padding: 0;
  font-family: Arial, sans-serif;
}

.ca-admin {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 220px;
  background-color: #334155;
  color: white;
  padding: 20px 0;
}

.logo {
  padding: 0 20px 20px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.logo h2 {
  margin: 0;
  font-size: 18px;
}

.menu {
  list-style: none;
  padding: 0;
  margin: 20px 0 0 0;
}

.menu li {
  padding: 12px 20px;
  cursor: pointer;
  transition: background-color 0.3s;
}

.menu li:hover {
  background-color: rgba(255, 255, 255, 0.1);
}

.menu li.active {
  background-color: #1e293b;
  border-left: 3px solid #3b82f6;
}

.content {
  flex: 1;
  padding: 30px;
  background-color: #f1f5f9;
}
</style>
