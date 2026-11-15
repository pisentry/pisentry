<script setup lang="ts">
import { computed } from 'vue'
import type { CategoryCount } from './api'
import { categories } from './categories'

const props = defineProps<{ top: CategoryCount[]; hint: string; showHosts?: boolean }>()
const emit = defineEmits<{ pick: [category: string] }>()

const byCat = computed(() => new Map(props.top.map((c) => [c.category, c])))
</script>

<template>
  <section class="panel">
    <div class="panel-head">
      <h2>Top 10</h2>
      <span class="hint">{{ hint }}</span>
    </div>
    <div class="top10">
      <button v-for="c in categories" :key="c.id" type="button" class="cat-row" @click="emit('pick', c.id)">
        <span class="cat-id">{{ c.id }}</span>
        <span class="cat-name">{{ c.name }}</span>
        <template v-if="byCat.get(c.id)">
          <span class="cat-count">
            {{ byCat.get(c.id)!.events }}<template v-if="showHosts"> · {{ byCat.get(c.id)!.hosts }} {{ byCat.get(c.id)!.hosts === 1 ? 'host' : 'hosts' }}</template>
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
</template>
