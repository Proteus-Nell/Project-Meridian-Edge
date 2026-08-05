import { defineConfig } from "vitest/config";

// Vite does not read PORT on its own; the preview harness assigns one via env.
const port = Number(process.env["PORT"]) || 5173;

const proxy = {
  "/v1": {
    target: "http://127.0.0.1:8000",
    changeOrigin: false,
    ws: true,
  },
};

// The page-level CSP the edge serves in production (deploy/nginx.conf,
// deploy/Caddyfile), with connect-src pointed at the local relay instead of the
// public host. `vite preview` serves the real built bundle, so applying the real
// headers here makes it a faithful rehearsal of the deployed site.
//
// This exists because its absence shipped a bug: `style-src 'self'` blocks the
// <style> elements xterm generates for its cell metrics, palette and cursor
// (see src/terminal/stylemirror.ts), and nothing on the local path applied the
// header, so the deployed terminal lost its column alignment, its colours and
// its cursor while dev looked perfect.
//
// Deliberately NOT on `server`: in dev Vite injects the app's own CSS as
// <style> elements, so a strict style-src would block style.css itself and
// break the dev server outright. Rehearse against `npm run build && npm run
// preview`, which is what production actually serves.
const PRODUCTION_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  `connect-src 'self' ws://127.0.0.1:8000 ws://localhost:${port}`,
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
].join("; ");

export default defineConfig({
  server: {
    port,
    proxy,
  },
  preview: {
    port,
    proxy,
    headers: {
      "Content-Security-Policy": PRODUCTION_CSP,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  },
  // The executor suites exercise real ML-KEM/ML-DSA/Argon2id per test; under full
  // parallelism CPU contention can push a single test past Vitest's 5s default.
  test: {
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
