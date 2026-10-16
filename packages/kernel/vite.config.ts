import { defineConfig } from "vite";

export default defineConfig({
  build: {
    target: "es2024",
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
  },
});
