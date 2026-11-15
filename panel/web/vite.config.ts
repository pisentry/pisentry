import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Builds into the Go package that embeds it. `npm run dev` proxies the API
// to a panel running on the default address.
export default defineConfig({
  plugins: [vue()],
  build: { outDir: '../internal/web/dist', emptyOutDir: true, assetsDir: 'assets' },
  server: { proxy: { '/api': 'http://127.0.0.1:8443' } },
})
