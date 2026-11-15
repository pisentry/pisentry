<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { get, ago, Unauthorized, type EventRow, type Host } from './api'
import { categories, categoryName, severities } from './categories'

const props = defineProps<{ host: string; category: string }>()
const emit = defineEmits<{ 'auth-lost': [] }>()

const host = ref(props.host)
const category = ref(props.category)
const severity = ref('')
const since = ref('24h')
const rows = ref<EventRow[]>([])
const hosts = ref<Host[]>([])
const error = ref('')
const loaded = ref(false)
const open = ref<{ key: string; json: string } | null>(null)

async function load() {
  try {
    rows.value = await get<EventRow[]>('events', {
      host: host.value,
      category: category.value,
      severity: severity.value,
      since: since.value,
      limit: '200',
    })
    error.value = ''
  } catch (e) {
    if (e instanceof Unauthorized) return emit('auth-lost')
    error.value = String(e)
  } finally {
    loaded.value = true
  }
}

async function show(e: EventRow) {
  const key = e.host + '/' + e.id
  if (open.value?.key === key) {
    open.value = null
    return
  }
  try {
    const raw = await get<unknown>('events/' + encodeURIComponent(e.host) + '/' + encodeURIComponent(e.id))
    open.value = { key, json: JSON.stringify(raw, null, 2) }
  } catch (err) {
    if (err instanceof Unauthorized) return emit('auth-lost')
    error.value = String(err)
  }
}

function clear() {
  host.value = ''
  category.value = ''
  severity.value = ''
  since.value = '24h'
}

function stamp(iso: string) {
  return new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

onMounted(async () => {
  try {
    hosts.value = await get<Host[]>('hosts')
  } catch {
    /* the filter just lists no hosts */
  }
  load()
})
watch([host, category, severity, since], load)
watch(
  () => [props.host, props.category],
  ([h, c]) => {
    host.value = h
    category.value = c
  },
)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Events</h1>
      <p class="sub">Newest first, up to 200. Select an event to see everything the agent sent.</p>
    </div>
  </div>

  <section class="panel">
    <form class="filters" @submit.prevent>
      <label class="select">
        <span>Host</span>
        <select v-model="host">
          <option value="">All</option>
          <option v-for="h in hosts" :key="h.name" :value="h.name">{{ h.name }}</option>
        </select>
      </label>
      <label class="select">
        <span>Category</span>
        <select v-model="category">
          <option value="">All</option>
          <option value="PS00">PS00 pisentry itself</option>
          <option v-for="c in categories" :key="c.id" :value="c.id">{{ c.id }} {{ c.name }}</option>
        </select>
      </label>
      <label class="select">
        <span>Severity</span>
        <select v-model="severity">
          <option value="">Any</option>
          <option v-for="s in severities" :key="s" :value="s">{{ s }} and up</option>
        </select>
      </label>
      <label class="select">
        <span>Since</span>
        <select v-model="since">
          <option value="1h">1 hour</option>
          <option value="24h">24 hours</option>
          <option value="168h">7 days</option>
          <option value="720h">30 days</option>
        </select>
      </label>
      <span class="filters-end">
        <span class="hint mono">{{ rows.length }} {{ rows.length === 1 ? 'event' : 'events' }}</span>
        <button v-if="host || category || severity || since !== '24h'" type="button" class="btn ghost sm" @click="clear">Clear</button>
      </span>
    </form>

    <p v-if="error" class="error pad" role="alert">{{ error }}</p>

    <div class="table-wrap">
      <table class="events">
        <thead><tr><th>Time</th><th>Severity</th><th>Host</th><th>Category</th><th>Summary</th></tr></thead>
        <tbody>
          <template v-for="e in rows" :key="e.host + e.id">
            <tr class="clickable" :class="{ open: open?.key === e.host + '/' + e.id }" :aria-expanded="open?.key === e.host + '/' + e.id" @click="show(e)">
              <td class="nowrap mono dim" :title="stamp(e.time)">{{ ago(e.time) }}</td>
              <td><span class="sev" :class="'sev-' + e.severity"><i></i>{{ e.severity }}</span></td>
              <td class="nowrap"><span class="host-name">{{ e.host }}</span></td>
              <td class="nowrap"><span class="mono faint">{{ e.category }}</span> {{ categoryName(e.category) }}</td>
              <td class="summary">{{ e.summary }}<div v-if="e.rule_id" class="rule mono">{{ e.rule_id }}</div></td>
            </tr>
            <tr v-if="open?.key === e.host + '/' + e.id" class="detail">
              <td colspan="5"><pre>{{ open.json }}</pre></td>
            </tr>
          </template>
          <tr v-if="loaded && rows.length === 0"><td colspan="5" class="empty">No events match.</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
