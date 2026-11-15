<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { get, ago, Unauthorized, type Host, type CategoryCount, type EventRow } from './api'
import { categories, categoryName } from './categories'

const emit = defineEmits<{
  'auth-lost': []
  'open-events': [filter: { host?: string; category?: string }]
}>()

const hosts = ref<Host[]>([])
const top = ref<CategoryCount[]>([])
const recent = ref<EventRow[]>([])
const error = ref('')
const loaded = ref(false)

async function load() {
  try {
    const [h, t, r] = await Promise.all([
      get<Host[]>('hosts'),
      get<CategoryCount[]>('top10', { since: '24h' }),
      get<EventRow[]>('events', { since: '24h', limit: '8' }),
    ])
    hosts.value = h
    top.value = t
    recent.value = r
    error.value = ''
  } catch (e) {
    if (e instanceof Unauthorized) return emit('auth-lost')
    error.value = String(e)
  } finally {
    loaded.value = true
  }
}

let timer: number | undefined
onMounted(() => {
  load()
  timer = window.setInterval(load, 15000)
})
onUnmounted(() => clearInterval(timer))

const byCat = computed(() => new Map(top.value.map((c) => [c.category, c])))
const quiet = computed(() => hosts.value.filter((h) => h.status === 'quiet').length)
const total24h = computed(() => top.value.reduce((n, c) => n + c.events, 0))
const highOrWorse = computed(() => top.value.filter((c) => c.worst === 'high' || c.worst === 'critical').length)
</script>

<template>
  <header class="page-head">
    <div>
      <h1>Overview</h1>
      <p class="muted">The last 24 hours across every Pi. Refreshes every 15 seconds.</p>
    </div>
  </header>

  <p v-if="error" class="error" role="alert">{{ error }}</p>

  <section class="tiles" aria-label="Summary">
    <div class="card tile"><span class="tile-label">Hosts</span><span class="tile-value">{{ hosts.length }}</span></div>
    <div class="card tile" :class="{ warn: quiet > 0 }">
      <span class="tile-label">Quiet hosts</span><span class="tile-value">{{ quiet }}</span>
    </div>
    <div class="card tile"><span class="tile-label">Events</span><span class="tile-value">{{ total24h }}</span></div>
    <div class="card tile" :class="{ bad: highOrWorse > 0 }">
      <span class="tile-label">Categories at high or critical</span><span class="tile-value">{{ highOrWorse }}</span>
    </div>
  </section>

  <section>
    <h2>Top 10</h2>
    <div class="top10">
      <button
        v-for="c in categories"
        :key="c.id"
        class="card cat"
        :class="byCat.get(c.id) ? 'sev-' + byCat.get(c.id)!.worst : 'clear'"
        @click="emit('open-events', { category: c.id })"
      >
        <span class="cat-id">{{ c.id }}</span>
        <span class="cat-name">{{ c.name }}</span>
        <span class="cat-count">
          <template v-if="byCat.get(c.id)">
            {{ byCat.get(c.id)!.events }} on {{ byCat.get(c.id)!.hosts }} {{ byCat.get(c.id)!.hosts === 1 ? 'host' : 'hosts' }}
          </template>
          <template v-else>Clear</template>
        </span>
      </button>
    </div>
  </section>

  <div class="split">
    <section>
      <h2>Hosts</h2>
      <div class="card table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Status</th><th>Last seen</th><th class="num">Events</th></tr></thead>
          <tbody>
            <tr v-for="h in hosts" :key="h.name" class="clickable" @click="emit('open-events', { host: h.name })">
              <td>{{ h.name }}<span v-if="h.reported_as && h.reported_as !== h.name" class="muted"> ({{ h.reported_as }})</span></td>
              <td><span class="pill" :class="'st-' + h.status">{{ h.status }}</span></td>
              <td>{{ ago(h.last_seen) }}</td>
              <td class="num">{{ h.events_24h }}</td>
            </tr>
            <tr v-if="loaded && hosts.length === 0">
              <td colspan="4" class="empty">
                No hosts yet. Add one with <code>sudo pisentry-panel host add NAME</code>.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Latest events</h2>
      <ul class="card feed">
        <li v-for="e in recent" :key="e.host + e.id">
          <span class="dot" :class="'sev-' + e.severity" aria-hidden="true"></span>
          <div>
            <div class="feed-summary">{{ e.summary }}</div>
            <div class="muted small">{{ e.host }} · {{ categoryName(e.category) }} · {{ ago(e.time) }}</div>
          </div>
        </li>
        <li v-if="loaded && recent.length === 0" class="empty">Nothing in the last 24 hours.</li>
      </ul>
    </section>
  </div>
</template>
