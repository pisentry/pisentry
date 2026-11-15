<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { get, ago, Unauthorized, type Host, type CategoryCount, type EventRow } from './api'
import { categories, categoryName, severities } from './categories'
import Icon from './Icon.vue'

const emit = defineEmits<{
  'auth-lost': []
  'open-events': [filter: { host?: string; category?: string }]
}>()

const ranges = [
  { id: '1h', label: '1h', hours: 1 },
  { id: '24h', label: '24h', hours: 24 },
  { id: '168h', label: '7d', hours: 168 },
  { id: '720h', label: '30d', hours: 720 },
] as const
type Range = (typeof ranges)[number]

const range = ref<Range>(ranges[1])
const hosts = ref<Host[]>([])
const top = ref<CategoryCount[]>([])
const events = ref<EventRow[]>([])
const error = ref('')
const loaded = ref(false)
const loadedAt = ref(Date.now())
const EVENT_CAP = 1000

async function load() {
  try {
    const since = range.value.id
    const [h, t, ev] = await Promise.all([
      get<Host[]>('hosts'),
      get<CategoryCount[]>('top10', { since }),
      get<EventRow[]>('events', { since, limit: String(EVENT_CAP) }),
    ])
    hosts.value = h
    top.value = t
    events.value = ev
    loadedAt.value = Date.now()
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
watch(range, load)

const byCat = computed(() => new Map(top.value.map((c) => [c.category, c])))
const okHosts = computed(() => hosts.value.filter((h) => h.status === 'ok').length)
const quiet = computed(() => hosts.value.filter((h) => h.status === 'quiet').length)
const waiting = computed(() => hosts.value.filter((h) => h.status === 'waiting').length)
const totalEvents = computed(() => top.value.reduce((n, c) => n + c.events, 0))
const hot = computed(() => top.value.filter((c) => c.worst === 'high' || c.worst === 'critical'))
const recent = computed(() => events.value.slice(0, 7))
const hostsShown = computed(() => hosts.value.slice(0, 8))

const rank = (s: string) => severities.indexOf(s as (typeof severities)[number])

// Events over the range in 48 buckets, each colored by its worst severity.
const BUCKETS = 48
const chart = computed(() => {
  const end = loadedAt.value
  const span = range.value.hours * 3600_000
  const step = span / BUCKETS
  const buckets = Array.from({ length: BUCKETS }, (_, i) => ({ n: 0, worst: '', start: end - span + i * step }))
  for (const e of events.value) {
    const i = Math.floor((Date.parse(e.time) - (end - span)) / step)
    if (i < 0 || i >= BUCKETS) continue
    const b = buckets[i]
    b.n++
    if (rank(e.severity) > rank(b.worst)) b.worst = e.severity
  }
  // A floor of 4 keeps a quiet day from drawing every single event full height.
  const max = Math.max(4, ...buckets.map((b) => b.n))
  const peak = buckets.reduce((p, b) => (b.n > p.n ? b : p), buckets[0])
  return { buckets, max, peak }
})

const axis = computed(() => {
  const h = range.value.hours
  const fmt = (x: number) => (x === 0 ? 'now' : x >= 48 ? `-${Math.round(x / 24)}d` : `-${x}h`)
  if (h === 1) return ['-60m', '-45m', '-30m', '-15m', 'now']
  return [h, (h * 3) / 4, h / 2, h / 4, 0].map(fmt)
})

function bucketLabel(b: { n: number; start: number }) {
  const t = new Date(b.start)
  const when = range.value.hours > 24 ? t.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return `${b.n} ${b.n === 1 ? 'event' : 'events'} from ${when}`
}

function clock(ms: number) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

// Copy the command that adds a Pi, until "Add a Pi" exists in the UI (#77).
const addCmd = 'sudo pisentry-panel host add NAME'
const copied = ref(false)
async function copyAdd() {
  try {
    await navigator.clipboard.writeText(addCmd)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    /* clipboard blocked: the command is on screen */
  }
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Fleet overview</h1>
      <p class="sub">
        {{ hosts.length }} {{ hosts.length === 1 ? 'Pi' : 'Pis' }} enrolled · updated {{ clock(loadedAt) }}
      </p>
    </div>
  </div>

  <div class="toolbar">
    <div class="seg" role="tablist" aria-label="Time range">
      <button
        v-for="r in ranges"
        :key="r.id"
        type="button"
        role="tab"
        :aria-selected="range.id === r.id"
        @click="range = r"
      >{{ r.label }}</button>
    </div>
    <button class="chip" type="button" :title="'Copy: ' + addCmd" @click="copyAdd">
      <code>{{ addCmd }}</code><Icon :name="copied ? 'check' : 'copy'" :size="14" />
    </button>
  </div>

  <p v-if="error" class="error" role="alert">{{ error }}</p>

  <section class="stats" aria-label="Summary">
    <div class="stat">
      <span class="label">Hosts</span>
      <span class="value">{{ hosts.length }}</span>
      <span class="hint">{{ okHosts }} reporting<template v-if="waiting"> · {{ waiting }} waiting</template></span>
    </div>
    <div class="stat" :class="{ warn: quiet > 0 }">
      <span class="label">Quiet</span>
      <span class="value">{{ quiet }}</span>
      <span class="hint">{{ quiet ? 'stopped sending' : 'all reporting' }}</span>
    </div>
    <div class="stat">
      <span class="label">Events</span>
      <span class="value">{{ totalEvents }}</span>
      <span class="hint">last {{ range.label }}</span>
    </div>
    <div class="stat" :class="{ bad: hot.length > 0 }">
      <span class="label">High or critical</span>
      <span class="value">{{ hot.length }}<small>/10</small></span>
      <span class="hint">{{ hot.length ? hot.map((c) => c.category).join(' ') : 'categories clear' }}</span>
    </div>
  </section>

  <section class="panel chart-panel" aria-label="Events over time">
    <div class="panel-head mono-head">
      <span>Events · {{ hosts.length }} {{ hosts.length === 1 ? 'host' : 'hosts' }} · last {{ range.label }}</span>
      <span v-if="chart.peak.n" class="peak">Peak {{ chart.peak.n }}</span>
    </div>
    <div class="bars">
      <div
        v-for="(b, i) in chart.buckets"
        :key="i"
        class="bar"
        :class="b.n ? 'sev-' + b.worst : 'zero'"
        :style="{ height: b.n ? Math.max(6, (b.n / chart.max) * 100) + '%' : '' }"
        :title="bucketLabel(b)"
      ></div>
    </div>
    <div class="axis"><span v-for="a in axis" :key="a">{{ a }}</span></div>
    <p v-if="events.length === EVENT_CAP" class="hint chart-note">Showing the newest {{ EVENT_CAP }} events.</p>
  </section>

  <section class="panel">
    <div class="panel-head">
      <h2>Top 10</h2>
      <span class="hint">The pisentry attack categories, worst severity in the last {{ range.label }}</span>
    </div>
    <div class="top10">
      <button
        v-for="c in categories"
        :key="c.id"
        type="button"
        class="cat-row"
        @click="emit('open-events', { category: c.id })"
      >
        <span class="cat-id">{{ c.id }}</span>
        <span class="cat-name">{{ c.name }}</span>
        <template v-if="byCat.get(c.id)">
          <span class="cat-count">
            {{ byCat.get(c.id)!.events }} · {{ byCat.get(c.id)!.hosts }} {{ byCat.get(c.id)!.hosts === 1 ? 'host' : 'hosts' }}
          </span>
          <span class="sev" :class="'sev-' + byCat.get(c.id)!.worst"><i></i>{{ byCat.get(c.id)!.worst }}</span>
        </template>
        <template v-else>
          <span class="cat-count"></span>
          <span class="sev clear"><i></i>clear</span>
        </template>
      </button>
    </div>
  </section>

  <div class="split">
    <section class="panel">
      <div class="panel-head">
        <h2>Hosts <span class="count">{{ hosts.length }}</span></h2>
        <a class="link" href="#/hosts">All hosts <Icon name="arrow" :size="14" /></a>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Host</th><th>Last seen</th><th class="num">Events 24h</th></tr></thead>
          <tbody>
            <tr v-for="h in hostsShown" :key="h.name" class="clickable" @click="emit('open-events', { host: h.name })">
              <td>
                <span class="status" :class="'st-' + h.status" :title="h.status"><i></i></span>
                <span class="host-name">{{ h.name }}</span>
                <span v-if="h.reported_as && h.reported_as !== h.name" class="faint mono"> {{ h.reported_as }}</span>
              </td>
              <td class="mono dim">{{ ago(h.last_seen) }}</td>
              <td class="num mono">{{ h.events_24h }}</td>
            </tr>
            <tr v-if="loaded && hosts.length === 0">
              <td colspan="3" class="empty">No hosts yet. Add one with <code>{{ addCmd }}</code>.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Latest events</h2>
        <a class="link" href="#/events">All events <Icon name="arrow" :size="14" /></a>
      </div>
      <ul class="feed">
        <li v-for="e in recent" :key="e.host + e.id">
          <span class="feed-dot" :class="'sev-' + e.severity" :title="e.severity"></span>
          <div class="feed-body">
            <div class="feed-summary">{{ e.summary }}</div>
            <div class="feed-meta mono">{{ e.host }} · {{ e.category }} {{ categoryName(e.category) }} · {{ ago(e.time) }}</div>
          </div>
        </li>
        <li v-if="loaded && recent.length === 0" class="empty">Nothing in the last {{ range.label }}.</li>
      </ul>
    </section>
  </div>
</template>
