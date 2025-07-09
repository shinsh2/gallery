import { fileURLToPath, URL } from 'node:url'

import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
// console.log(import.meta.env);
export default defineConfig(({ mode }) => {
  // console.log('mode:', mode);
  const env = loadEnv(mode, process.cwd(), '')
  // console.log('env:', env);
  return {
    server: {
      proxy: {
        "/v1/api": {
          target: env.VITE_API_URL,
          changeOrigin: true
        }
      }
    },
    plugins: [
      vue(),
    ],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url))
      }
    }
  }
})
