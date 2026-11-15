<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { get, ago, Unauthorized, type Host } from './api'

const emit = defineEmits<{
  'auth-lost': []
  'open-events': [filter: { host?: string }]
}>()

const hosts = ref<Host[]>([])
const error = ref('')
const loaded = ref(false)

async function load() {
  try {
    hosts.value = await get<Host[]>('hosts')
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

const counts = computed(() => ({
  ok: hosts.value.filter((h) => h.status === 'ok').length,
  quiet: hosts.value.filter((h) => h.status === 'quiet').length,
  waiting: hosts.value.filter((h) => h.status === 'waiting').length,
}))

const statusText: Record<Host['status'], string> = {
  ok: 'Reporting',
  quiet: 'Quiet',
  waiting: 'Waiting for first event',
}

function day(iso: string) {
  return new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' })
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Hosts</h1>
      <p class="sub">
        {{ counts.ok }} reporting · {{ counts.quiet }} quiet · {{ counts.waiting }} waiting
      </p>
    </div>
  </div>

  <p v-if="error" class="error" role="alert">{{ error }}</p>

  <section class="panel">
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Host</th><th>Status</th><th>Reports as</th><th>Added</th><th>Last seen</th><th class="num">Events 24h</th></tr>
        </thead>
        <tbody>
          <tr v-for="h in hosts" :key="h.name" class="clickable" @click="emit('open-events', { host: h.name })">
            <td><span class="host-name">{{ h.name }}</span></td>
            <td><span class="status" :class="'st-' + h.status"><i></i>{{ statusText[h.status] }}</span></td>
            <td class="mono dim">{{ h.reported_as || '—' }}</td>
            <td class="mono dim">{{ day(h.created_at) }}</td>
            <td class="mono dim">{{ ago(h.last_seen) }}</td>
            <td class="num mono">{{ h.events_24h }}</td>
          </tr>
          <tr v-if="loaded && hosts.length === 0">
            <td colspan="6" class="empty">No hosts yet. Add one with <code>sudo pisentry-panel host add NAME</code>.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
