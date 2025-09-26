import { createRouter, createWebHashHistory } from 'vue-router'
import PortForwardView from '../views/PortForwardView.vue'
import WebServiceView from '../views/WebServiceView.vue'
import IPListsView from '../views/IPListsView.vue'
import LogsView from '../views/LogsView.vue'
import GlobalACLView from '../views/GlobalACLView.vue'
import SettingsView from '../views/SettingsView.vue'
import CertificatesView from '../views/CertificatesView.vue'
import WAFView from '../views/WAFView.vue'

const routes = [
  { path: '/', name: 'PortForward', component: PortForwardView },
  { path: '/web-service', name: 'WebService', component: WebServiceView },
  { path: '/ip-lists', name: 'IPLists', component: IPListsView },
  { path: '/waf', name: 'WAF', component: WAFView },
  { path: '/global-acl', name: 'GlobalACL', component: GlobalACLView },
  { path: '/certificates', name: 'Certificates', component: CertificatesView },
  { path: '/logs', name: 'Logs', component: LogsView },
  { path: '/settings', name: 'Settings', component: SettingsView },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

export default router