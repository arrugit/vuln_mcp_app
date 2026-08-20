// Import defineConfig from vitest/config (not "vite") so the `test` block below
// is type-checked correctly. vitest/config re-exports Vite's defineConfig with
// the Vitest `test` field merged in — without this, `tsc -b` (run by
// `npm run build`) rejects `test` as an unknown property.
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Vite config for the control-plane UI.
// DEP-004: dev server binds to localhost. The API is proxied so the browser
// talks to a single origin during development.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
  },
});
