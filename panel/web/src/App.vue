<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { getToken, setToken, get, hostHref, Unauthorized, type Host } from './api'
import Icon from './Icon.vue'
import Mark from './Mark.vue'
import Overview from './Overview.vue'
import Events from './Events.vue'
import Hosts from './Hosts.vue'
import HostDetail from './HostDetail.vue'

type Route = { page: 'overview' } | { page: 'events' } | { page: 'hosts' } | { page: 'host'; name: string }

const token = ref(getToken())
const draft = ref('')
const loginError = ref('')
const route = ref<Route>(routeFromHash())
const eventsHost = ref('')
const eventsCategory = ref('')

function routeFromHash(): Route {
  const h = location.hash
  const m = h.match(/^#\/hosts\/(.+)$/)
  if (m) {
    try {
      return { page: 'host', name: decodeURIComponent(m[1]) }
    } catch {
      return { page: 'hosts' }
    }
  }
  if (h.startsWith('#/events')) return { page: 'events' }
  if (h.startsWith('#/hosts')) return { page: 'hosts' }
  return { page: 'overview' }
}
function onHash() {
  route.value = routeFromHash()
}
onMounted(() => window.addEventListener('hashchange', onHash))
onUnmounted(() => window.removeEventListener('hashchange', onHash))

const crumb = computed(() => {
  const r = route.value
  if (r.page === 'host') return r.name
  return { overview: 'Overview', events: 'Events', hosts: 'Hosts' }[r.page]
})
const current = (page: Route['page']) => (route.value.page === page ? 'page' : undefined)
const currentHost = (name: string) =>
  route.value.page === 'host' && route.value.name === name ? 'page' : undefined

// Theme: dark by default, remembered per browser.
const THEME_KEY = 'pisentry-panel-theme'
function readTheme(): 'dark' | 'light' {
  try {
    return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}
const theme = ref(readTheme())
document.documentElement.dataset.theme = theme.value
function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  document.documentElement.dataset.theme = theme.value
  try {
    localStorage.setItem(THEME_KEY, theme.value)
  } catch {
    /* not remembered, still applied */
  }
}

// The sidebar's host list, refreshed like the pages.
const hosts = ref<Host[]>([])
const SIDE_HOSTS = 8
const sideHosts = computed(() => {
  // Quiet hosts first, so a Pi that stopped reporting is the first thing seen.
  const order = { quiet: 0, ok: 1, waiting: 2 }
  return [...hosts.value].sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name)).slice(0, SIDE_HOSTS)
})
const quietCount = computed(() => hosts.value.filter((h) => h.status === 'quiet').length)
async function loadHosts() {
  if (!token.value) return
  try {
    hosts.value = await get<Host[]>('hosts')
  } catch (e) {
    if (e instanceof Unauthorized) onAuthLost()
  }
}
let timer: number | undefined
onMounted(() => {
  loadHosts()
  timer = window.setInterval(loadHosts, 15000)
})
onUnmounted(() => clearInterval(timer))
watch(token, loadHosts)

async function login() {
  loginError.value = ''
  setToken(draft.value.trim())
  try {
    await get('hosts')
    token.value = draft.value.trim()
    draft.value = ''
  } catch (e) {
    setToken('')
    loginError.value = e instanceof Unauthorized ? 'That token is not right.' : String(e)
  }
}

function logout() {
  setToken('')
  token.value = ''
  hosts.value = []
}

function onAuthLost() {
  logout()
  loginError.value = 'Your token stopped working. Enter it again.'
}

function openEvents(filter: { host?: string; category?: string }) {
  eventsHost.value = filter.host ?? ''
  eventsCategory.value = filter.category ?? ''
  location.hash = '#/events'
}
</script>

<template>
  <div v-if="!token" class="login">
    <form class="login-card" @submit.prevent="login">
      <Mark :size="36" />
      <h1>Sign in to pisentry</h1>
      <p class="muted">
        Paste the admin token. Run <code>sudo pisentry-panel admin-token</code> on the panel's host to see it.
      </p>
      <label class="field">
        <span>Admin token</span>
        <input v-model="draft" type="password" autocomplete="off" spellcheck="false" placeholder="psa_…" required />
      </label>
      <p v-if="loginError" class="error" role="alert">{{ loginError }}</p>
      <button type="submit" class="btn primary block">Sign in</button>
    </form>
  </div>

  <div v-else class="shell">
    <aside class="side">
      <div class="side-brand"><Mark :size="22" /><span>pisentry</span></div>

      <nav class="side-nav" aria-label="Main">
        <div class="side-group">
          <span class="side-label">Monitor</span>
          <a href="#/" :aria-current="current('overview')"><Icon name="home" />Overview</a>
          <a href="#/events" :aria-current="current('events')" @click="eventsHost = ''; eventsCategory = ''">
            <Icon name="events" />Events
          </a>
        </div>

        <div class="side-group">
          <span class="side-label">Fleet</span>
          <a href="#/hosts" :aria-current="current('hosts')">
            <Icon name="hosts" />Hosts
            <span v-if="quietCount" class="side-badge warn" :title="quietCount + ' quiet'">{{ quietCount }} quiet</span>
            <span v-else class="side-badge">{{ hosts.length }}</span>
          </a>
          <div class="side-hosts">
            <a
              v-for="h in sideHosts"
              :key="h.name"
              :href="hostHref(h.name)"
              :aria-current="currentHost(h.name)"
              :title="h.name + ' · ' + h.status"
            >
              <span class="status" :class="'st-' + h.status"><i></i></span>
              <span class="side-host-name">{{ h.name }}</span>
            </a>
            <a v-if="hosts.length > SIDE_HOSTS" href="#/hosts" class="side-more">+{{ hosts.length - SIDE_HOSTS }} more</a>
          </div>
        </div>
      </nav>

      <div class="side-foot">
        <button class="side-btn" type="button" @click="toggleTheme">
          <Icon :name="theme === 'dark' ? 'sun' : 'moon'" />{{ theme === 'dark' ? 'Light mode' : 'Dark mode' }}
        </button>
        <button class="side-btn" type="button" @click="logout"><Icon name="logout" />Sign out</button>
      </div>
    </aside>

    <div class="frame">
      <header class="topbar">
        <span v-if="route.page === 'host'" class="crumb">
          <a href="#/hosts">Hosts</a><span class="crumb-sep" aria-hidden="true">/</span><span class="crumb-here">{{ route.name }}</span>
        </span>
        <span v-else class="crumb">{{ crumb }}</span>
        <span class="live"><span class="live-dot" aria-hidden="true"></span>Live</span>
      </header>
      <main class="content">
        <Overview v-if="route.page === 'overview'" @auth-lost="onAuthLost" @open-events="openEvents" />
        <Hosts v-else-if="route.page === 'hosts'" @auth-lost="onAuthLost" />
        <HostDetail
          v-else-if="route.page === 'host'"
          :name="route.name"
          @auth-lost="onAuthLost"
          @open-events="openEvents"
        />
        <Events v-else :host="eventsHost" :category="eventsCategory" @auth-lost="onAuthLost" />
      </main>
    </div>
  </div>
</template>
