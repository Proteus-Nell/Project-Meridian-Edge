import { defineConfig } from "vite";

// Vite does not read PORT on its own; the preview harness assigns one via env.
const port = Number(process.env["PORT"]) || 5173;

export default defineConfig({
  server: {
    port,
    proxy: {
      "/v1": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
      },
    },
  },
});
