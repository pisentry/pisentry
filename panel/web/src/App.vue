<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { getToken, setToken, get, Unauthorized } from './api'
import Icon from './Icon.vue'
import Mark from './Mark.vue'
import Overview from './Overview.vue'
import Events from './Events.vue'
import Hosts from './Hosts.vue'

type Page = 'overview' | 'events' | 'hosts'

const token = ref(getToken())
const draft = ref('')
const loginError = ref('')
const page = ref<Page>(pageFromHash())
const eventsHost = ref('')
const eventsCategory = ref('')

const titles: Record<Page, string> = { overview: 'Overview', events: 'Events', hosts: 'Hosts' }
const title = computed(() => titles[page.value])

function pageFromHash(): Page {
  if (location.hash.startsWith('#/events')) return 'events'
  if (location.hash.startsWith('#/hosts')) return 'hosts'
  return 'overview'
}
function onHash() {
  page.value = pageFromHash()
}
onMounted(() => window.addEventListener('hashchange', onHash))
onUnmounted(() => window.removeEventListener('hashchange', onHash))

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
        <a href="#/" :aria-current="page === 'overview' ? 'page' : undefined"><Icon name="home" />Overview</a>
        <a
          href="#/events"
          :aria-current="page === 'events' ? 'page' : undefined"
          @click="eventsHost = ''; eventsCategory = ''"
        ><Icon name="events" />Events</a>
        <a href="#/hosts" :aria-current="page === 'hosts' ? 'page' : undefined"><Icon name="hosts" />Hosts</a>
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
        <span class="crumb">{{ title }}</span>
        <span class="live"><span class="live-dot" aria-hidden="true"></span>Live</span>
      </header>
      <main class="content">
        <Overview v-if="page === 'overview'" @auth-lost="onAuthLost" @open-events="openEvents" />
        <Hosts v-else-if="page === 'hosts'" @auth-lost="onAuthLost" @open-events="openEvents" />
        <Events v-else :host="eventsHost" :category="eventsCategory" @auth-lost="onAuthLost" />
      </main>
    </div>
  </div>
</template>
