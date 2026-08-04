// B5 (footprint) - frontend bundle-size of the PQC libraries against the classical baseline.
// Bundles the PQC primitives (@noble/post-quantum) and the classical baseline (@noble/curves) 
// each on their own, minified the same way the production build is 
// (Vite's default minifier, unconfig'd in both), and reports raw + gzipped size.
//
// Each row is a standalone bundled size, not the marginal cost of adding that
// library to this client: @noble/hashes is already a client dependency, so
// modules shared with it (hashes/utils.js, and curves/utils.js pulled in by
// ml-dsa) are counted here but shipped either way. Read the rows as a
// like-for-like library comparison and an upper bound on the true delta.
//
// Run:  node bench/bundle_size.mjs                 # table to stdout
//       node bench/bundle_size.mjs --json          # JSON to stdout
//       node bench/bundle_size.mjs --out bench/out # table + <out>/bundle.json
//
// The --out file is what bench/consolidate.py reads for the B5 bundle half;
// without it the numbers only ever existed on someone's terminal.
//
// vite is resolved from client/node_modules regardless of cwd.


import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_DIR = path.join(HERE, "..", "client");

const require = createRequire(path.join(CLIENT_DIR, "package.json"));
const { build } = await import(pathToFileURL(require.resolve("vite")));

const ENTRIES = {
  "@noble/post-quantum (ML-KEM + ML-DSA)": `
    import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
    import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
    export const used = [ml_kem768, ml_dsa65];
  `,
  "@noble/curves (X25519 + Ed25519)": `
    import { ed25519, x25519 } from "@noble/curves/ed25519.js";
    export const used = [ed25519, x25519];
  `,
};

async function bundleSize(source) {
  // The temp entry must live inside client/ so Rolldown resolves @noble from
  // client/node_modules (module resolution starts at the entry's directory).
  const dir = mkdtempSync(path.join(CLIENT_DIR, ".bench-bundle-"));
  const entry = path.join(dir, "entry.mjs");
  writeFileSync(entry, source, "utf8");
  try {
    const result = await build({
      root: CLIENT_DIR,
      logLevel: "silent",
      configFile: false,
      build: {
        write: false,
        minify: true, // vite 8 default minifier (the production build uses it too)
        lib: { entry, formats: ["es"], fileName: "b" },
        rollupOptions: { treeshake: true },
      },
    });
    const outputs = Array.isArray(result) ? result : [result];
    const chunk = outputs[0].output.find((o) => o.type === "chunk");
    const code = Buffer.from(chunk.code, "utf8");
    return { raw: code.length, gzip: gzipSync(code).length };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const rows = [];
for (const [name, source] of Object.entries(ENTRIES)) {
  rows.push({ library: name, ...(await bundleSize(source)) });
}

const payload = { suite: "B5", metric: "bundle-size", rows };

// --out <dir> writes <dir>/bundle.json and still prints the table: the file is
// for consolidate.py, the table for whoever ran the command.
const outIndex = process.argv.indexOf("--out");
const outDir = outIndex === -1 ? null : process.argv[outIndex + 1];
if (outIndex !== -1 && (outDir === undefined || outDir.startsWith("--"))) {
  console.error("--out needs a directory, e.g. --out bench/out");
  process.exit(2);
}
if (outDir !== null) {
  mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, "bundle.json");
  writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  console.log(`wrote ${file}\n`);
}

const asJson = process.argv.includes("--json");
if (asJson) {
  console.log(JSON.stringify(payload, null, 2));
} else {
  const fmt = (n) => `${(n / 1024).toFixed(1)} kB`;
  console.log("B5 - frontend bundle-size (minified, own chunk)\n");
  const w = Math.max(...rows.map((r) => r.library.length));
  console.log(`  ${"library".padEnd(w)}  ${"minified".padStart(12)}  ${"gzipped".padStart(12)}`);
  console.log(`  ${"-".repeat(w)}  ${"-".repeat(12)}  ${"-".repeat(12)}`);
  for (const r of rows) {
    console.log(`  ${r.library.padEnd(w)}  ${fmt(r.raw).padStart(12)}  ${fmt(r.gzip).padStart(12)}`);
  }
  const pqc = rows[0];
  const classical = rows[1];
  console.log(
    `\n  PQC vs classical, standalone + gzipped: ${fmt(pqc.gzip - classical.gzip)} ` +
      `(${(pqc.gzip / classical.gzip).toFixed(1)}x).`,
  );
}
