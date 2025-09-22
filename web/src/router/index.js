import { createRouter, createWebHashHistory } from 'vue-router'
import PortForwardView from '../views/PortForwardView.vue'
import IPListsView from '../views/IPListsView.vue'
import LogsView from '../views/LogsView.vue'
import GlobalACLView from '../views/GlobalACLView.vue'
import SettingsView from '../views/SettingsView.vue' // ����

const routes = [
  { path: '/', name: 'PortForward', component: PortForwardView },
  { path: '/ip-lists', name: 'IPLists', component: IPListsView },
  { path: '/logs', name: 'Logs', component: LogsView },
  { path: '/global-acl', name: 'GlobalACL', component: GlobalACLView },
  { path: '/settings', name: 'Settings', component: SettingsView }, // ����
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

export default router