<script setup lang="ts">
import { computed } from 'vue'
import type { EventRow } from './api'
import { severities } from './categories'
import { EVENT_CAP, type Range } from './ranges'

const props = defineProps<{ events: EventRow[]; range: Range; end: number; title: string }>()

const rank = (s: string) => severities.indexOf(s as (typeof severities)[number])

// Events over the range in 48 buckets, each colored by its worst severity.
const BUCKETS = 48
const chart = computed(() => {
  const span = props.range.hours * 3600_000
  const start = props.end - span
  const step = span / BUCKETS
  const buckets = Array.from({ length: BUCKETS }, (_, i) => ({ n: 0, worst: '', start: start + i * step }))
  for (const e of props.events) {
    const i = Math.floor((Date.parse(e.time) - start) / step)
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
  const h = props.range.hours
  if (h === 1) return ['-60m', '-45m', '-30m', '-15m', 'now']
  const fmt = (x: number) => (x === 0 ? 'now' : x >= 48 ? `-${Math.round(x / 24)}d` : `-${x}h`)
  return [h, (h * 3) / 4, h / 2, h / 4, 0].map(fmt)
})

function bucketLabel(b: { n: number; start: number }) {
  const t = new Date(b.start)
  const when =
    props.range.hours > 24
      ? t.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      : t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return `${b.n} ${b.n === 1 ? 'event' : 'events'} from ${when}`
}
</script>

<template>
  <section class="panel chart-panel" aria-label="Events over time">
    <div class="panel-head mono-head">
      <span>{{ title }}</span>
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
</template>
