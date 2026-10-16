// T-5 T-37
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";

const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self'",
  "img-src data:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
].join("; ");

export default defineConfig({
  root: fileURLToPath(new URL("app", import.meta.url)),
  build: {
    target: "es2024",
    outDir: fileURLToPath(new URL("../dist/e2e", import.meta.url)),
    emptyOutDir: true,
  },
  preview: {
    headers: {
      "Content-Security-Policy": csp,
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
});
