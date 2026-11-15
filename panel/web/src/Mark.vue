<script setup lang="ts">
defineProps<{ size?: number }>()
</script>

<template>
  <svg :width="size ?? 22" :height="size ?? 22" viewBox="0 0 24 24" aria-hidden="true" class="mark">
    <path d="M12 2 4 5v6.5c0 4.6 3.3 8.8 8 10.5 4.7-1.7 8-5.9 8-10.5V5z" fill="var(--brand)" />
    <path d="M8.5 12.2 11 14.6l4.6-5" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
  </svg>
</template>
