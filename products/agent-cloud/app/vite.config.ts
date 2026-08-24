import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    rolldownOptions: {
      output: {
        manualChunks: (id) => id.includes("node_modules/@auth0/") ? "auth-runtime" : id.includes("node_modules/convex/") ? "convex-runtime" : undefined,
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 6670,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 6670,
    strictPort: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
  },
});
