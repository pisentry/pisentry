<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { get, ago, Unauthorized, type Host, type CategoryCount, type EventRow } from './api'
import { categoryName } from './categories'
import { ranges, EVENT_CAP, type Range } from './ranges'
import Icon from './Icon.vue'
import EventsChart from './EventsChart.vue'
import Top10List from './Top10List.vue'

const props = defineProps<{ name: string }>()
const emit = defineEmits<{
  'auth-lost': []
  'open-events': [filter: { host?: string; category?: string }]
}>()

const range = ref<Range>(ranges[1])
const host = ref<Host | null>(null)
const top = ref<CategoryCount[]>([])
const events = ref<EventRow[]>([])
const error = ref('')
const loaded = ref(false)
const loadedAt = ref(Date.now())

async function load() {
  const name = props.name
  try {
    const since = range.value.id
    const [h, t, ev] = await Promise.all([
      get<Host[]>('hosts'),
      get<CategoryCount[]>('top10', { since, host: name }),
      get<EventRow[]>('events', { since, host: name, limit: String(EVENT_CAP) }),
    ])
    if (name !== props.name) return // the user moved to another host meanwhile
    host.value = h.find((x) => x.name === name) ?? null
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
watch(
  () => props.name,
  () => {
    host.value = null
    top.value = []
    events.value = []
    loaded.value = false
    load()
  },
)

const statusText: Record<Host['status'], string> = {
  ok: 'Reporting',
  quiet: 'Quiet',
  waiting: 'Waiting',
}
const total = computed(() => top.value.reduce((n, c) => n + c.events, 0))
const hot = computed(() => top.value.filter((c) => c.worst === 'high' || c.worst === 'critical'))
const recent = computed(() => events.value.slice(0, 12))

function day(iso: string) {
  return new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' })
}
</script>

<template>
  <template v-if="host">
    <div class="page-head host-head">
      <div>
        <h1>{{ host.name }}</h1>
        <p class="sub">
          <template v-if="host.reported_as && host.reported_as !== host.name">Reports as <span class="mono">{{ host.reported_as }}</span> · </template>
          Added {{ day(host.created_at) }}
        </p>
      </div>
      <span class="status big" :class="'st-' + host.status"><i></i>{{ statusText[host.status] }}</span>
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
      <button class="btn ghost sm" type="button" @click="emit('open-events', { host: host.name })">
        All events for {{ host.name }} <Icon name="arrow" :size="14" />
      </button>
    </div>

    <p v-if="error" class="error" role="alert">{{ error }}</p>

    <section class="stats" aria-label="Summary">
      <div class="stat" :class="{ warn: host.status === 'quiet' }">
        <span class="label">Last seen</span>
        <span class="value">{{ ago(host.last_seen) }}</span>
        <span class="hint">{{ host.status === 'quiet' ? 'stopped sending' : host.status === 'waiting' ? 'no events yet' : 'sending' }}</span>
      </div>
      <div class="stat">
        <span class="label">Events</span>
        <span class="value">{{ total }}</span>
        <span class="hint">last {{ range.label }}</span>
      </div>
      <div class="stat" :class="{ bad: hot.length > 0 }">
        <span class="label">High or critical</span>
        <span class="value">{{ hot.length }}<small>/10</small></span>
        <span class="hint">{{ hot.length ? hot.map((c) => c.category).join(' ') : 'categories clear' }}</span>
      </div>
      <div class="stat">
        <span class="label">Categories hit</span>
        <span class="value">{{ top.filter((c) => c.category !== 'PS00').length }}<small>/10</small></span>
        <span class="hint">last {{ range.label }}</span>
      </div>
    </section>

    <EventsChart :events="events" :range="range" :end="loadedAt" :title="`Events · ${host.name} · last ${range.label}`" />

    <Top10List
      :top="top"
      :hint="`Worst severity on ${host.name} in the last ${range.label}`"
      @pick="(c) => emit('open-events', { host: host!.name, category: c })"
    />

    <section class="panel">
      <div class="panel-head">
        <h2>Latest events</h2>
        <button class="link" type="button" @click="emit('open-events', { host: host.name })">
          All events <Icon name="arrow" :size="14" />
        </button>
      </div>
      <div class="table-wrap">
        <table class="events">
          <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Summary</th></tr></thead>
          <tbody>
            <tr v-for="e in recent" :key="e.id">
              <td class="nowrap mono dim">{{ ago(e.time) }}</td>
              <td><span class="sev" :class="'sev-' + e.severity"><i></i>{{ e.severity }}</span></td>
              <td class="nowrap"><span class="mono faint">{{ e.category }}</span> {{ categoryName(e.category) }}</td>
              <td class="summary">{{ e.summary }}<div v-if="e.rule_id" class="rule mono">{{ e.rule_id }}</div></td>
            </tr>
            <tr v-if="recent.length === 0"><td colspan="4" class="empty">Nothing in the last {{ range.label }}.</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </template>

  <section v-else-if="loaded" class="panel">
    <p class="empty">
      No host called <span class="mono">{{ name }}</span>. It may have been removed.
      <a class="link" href="#/hosts">Back to hosts</a>
    </p>
  </section>
</template>
