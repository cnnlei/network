import { createRouter, createWebHashHistory } from 'vue-router'
import PortForwardView from '../views/PortForwardView.vue'
import IPListsView from '../views/IPListsView.vue'
import LogsView from '../views/LogsView.vue'

const routes = [
  { path: '/', name: 'PortForward', component: PortForwardView },
  { path: '/ip-lists', name: 'IPLists', component: IPListsView },
  { path: '/logs', name: 'Logs', component: LogsView },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

export default router