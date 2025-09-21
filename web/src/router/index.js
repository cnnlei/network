// cnnlei/network/network-33ab537e85847c302b55c126d843f77b047a1244/web/src/router/index.js
import { createRouter, createWebHashHistory } from 'vue-router'
import PortForwardView from '../views/PortForwardView.vue'
import IPListsView from '../views/IPListsView.vue'
import LogsView from '../views/LogsView.vue'
import GlobalACLView from '../views/GlobalACLView.vue' // 新增

const routes = [
  { path: '/', name: 'PortForward', component: PortForwardView },
  { path: '/ip-lists', name: 'IPLists', component: IPListsView },
  { path: '/logs', name: 'Logs', component: LogsView },
  { path: '/global-acl', name: 'GlobalACL', component: GlobalACLView }, // 新增
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

export default router