import { defineConfig } from "vitest/config";

// Vite does not read PORT on its own; the preview harness assigns one via env.
const port = Number(process.env["PORT"]) || 5173;

export default defineConfig({
  server: {
    port,
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
        ws: true,
      },
    },
  },
  // The executor suites exercise real ML-KEM/ML-DSA/Argon2id per test; under full
  // parallelism CPU contention can push a single test past Vitest's 5s default.
  test: {
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
