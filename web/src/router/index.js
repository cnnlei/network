import { createRouter, createWebHashHistory } from 'vue-router'
import PortForwardView from '../views/PortForwardView.vue'
import WebServiceView from '../views/WebServiceView.vue' // 新增
import IPListsView from '../views/IPListsView.vue'
import LogsView from '../views/LogsView.vue'
import GlobalACLView from '../views/GlobalACLView.vue'
import SettingsView from '../views/SettingsView.vue'

const routes = [
  { path: '/', name: 'PortForward', component: PortForwardView },
  { path: '/web-service', name: 'WebService', component: WebServiceView }, // 新增
  { path: '/ip-lists', name: 'IPLists', component: IPListsView },
  { path: '/logs', name: 'Logs', component: LogsView },
  { path: '/global-acl', name: 'GlobalACL', component: GlobalACLView },
  { path: '/settings', name: 'Settings', component: SettingsView },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

export default router