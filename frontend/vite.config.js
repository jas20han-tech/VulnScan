import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend routes mount at /targets, /scans, /findings (no /api prefix).
// The frontend calls /api/... throughout; Vite rewrites /api/* -> /* and
// proxies to the backend on :8000 during dev (avoids CORS in the browser).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
