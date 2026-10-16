// T-5 T-37
import { defineConfig, devices } from "@playwright/test";

const port = 4180;
const ci = process.env["CI"] !== undefined;
const vite = "npx vite --config e2e/vite.config.ts";

export default defineConfig({
  testDir: "./e2e",
  retries: 0,
  forbidOnly: ci,
  fullyParallel: true,
  reporter: ci ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${String(port)}`,
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: `${vite} build && ${vite} preview --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: false,
  },
});
