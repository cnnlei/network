// cnnlei/network/network-33ab537e85847c302b55c126d843f77b047a1244/web/src/App.vue
<script setup>
</script>

<template>
  <div id="app-layout">
    <aside class="sidebar">
      <div class="logo">
        <h2>Go Forwarder</h2>
      </div>
      <nav class="navigation">
        <router-link to="/">端口转发</router-link>
        <router-link to="/ip-lists">IP 名单</router-link>
        <router-link to="/global-acl">全局访问控制</router-link> <router-link to="/logs">历史日志</router-link>
      </nav>
    </aside>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<style>
:root {
  --sidebar-width: 240px;
  --bg-color: #f4f6f9;
  --sidebar-bg: #2c3e50;
  --sidebar-text: #ecf0f1;
  --sidebar-text-hover: #ffffff;
  --sidebar-active-bg: #34495e;
  --primary-color: #007bff;
  --border-color: #e0e0e0;
}
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background-color: var(--bg-color);
}
</style>

<style scoped>
#app-layout {
  display: flex;
}
.sidebar {
  width: var(--sidebar-width);
  height: 100vh;
  background-color: var(--sidebar-bg);
  color: var(--sidebar-text);
  position: fixed;
  top: 0;
  left: 0;
  display: flex;
  flex-direction: column;
}
.logo {
  padding: 1.5rem;
  text-align: center;
  border-bottom: 1px solid #34495e;
}
.logo h2 {
  margin: 0;
}
.navigation {
  display: flex;
  flex-direction: column;
  margin-top: 1rem;
}
.navigation a {
  padding: 1rem 1.5rem;
  color: var(--sidebar-text);
  text-decoration: none;
  transition: background-color 0.2s;
  border-left: 4px solid transparent;
}
.navigation a:hover {
  background-color: var(--sidebar-active-bg);
  color: var(--sidebar-text-hover);
}
.navigation a.router-link-exact-active {
  background-color: var(--sidebar-active-bg);
  color: var(--sidebar-text-hover);
  border-left-color: var(--primary-color);
  font-weight: 500;
}
.main-content {
  margin-left: var(--sidebar-width);
  width: calc(100% - var(--sidebar-width));
  padding: 2rem;
  box-sizing: border-box;
}
</style>