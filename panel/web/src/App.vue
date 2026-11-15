<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { getToken, setToken, get, Unauthorized } from './api'
import Overview from './Overview.vue'
import Events from './Events.vue'

type Page = 'overview' | 'events'

const token = ref(getToken())
const draft = ref('')
const loginError = ref('')
const page = ref<Page>(pageFromHash())
const eventsHost = ref('')
const eventsCategory = ref('')

function pageFromHash(): Page {
  return location.hash.startsWith('#/events') ? 'events' : 'overview'
}
function onHash() {
  page.value = pageFromHash()
}
onMounted(() => window.addEventListener('hashchange', onHash))
onUnmounted(() => window.removeEventListener('hashchange', onHash))

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
    <form class="card login-card" @submit.prevent="login">
      <div class="brand"><span class="mark" aria-hidden="true"></span>pisentry</div>
      <h1>Sign in to the panel</h1>
      <p class="muted">
        Paste the admin token. Run <code>sudo pisentry-panel admin-token</code> on the panel's host to see it.
      </p>
      <label for="tok">Admin token</label>
      <input id="tok" v-model="draft" type="password" autocomplete="off" spellcheck="false" placeholder="psa_..." required />
      <p v-if="loginError" class="error" role="alert">{{ loginError }}</p>
      <button type="submit" class="primary">Sign in</button>
    </form>
  </div>

  <div v-else class="shell">
    <aside class="side">
      <div class="brand"><span class="mark" aria-hidden="true"></span>pisentry</div>
      <nav>
        <a href="#/" :aria-current="page === 'overview' ? 'page' : undefined">Overview</a>
        <a href="#/events" :aria-current="page === 'events' ? 'page' : undefined" @click="eventsHost = ''; eventsCategory = ''">Events</a>
      </nav>
      <button class="ghost signout" @click="logout">Sign out</button>
    </aside>
    <main>
      <Overview v-if="page === 'overview'" @auth-lost="onAuthLost" @open-events="openEvents" />
      <Events v-else :host="eventsHost" :category="eventsCategory" @auth-lost="onAuthLost" />
    </main>
  </div>
</template>
