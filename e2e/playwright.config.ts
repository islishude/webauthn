/// <reference types="node" />

import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  fullyParallel: false,
  retries: process.env.CI ? 2 : 0,
  reporter: [["html"], ["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "https://localhost:8443",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium-webauthn",
      use: {
        ...devices["Desktop Chrome"],
        baseURL: process.env.E2E_BASE_URL ?? "https://localhost:8443",
        ignoreHTTPSErrors: true,
        trace: "retain-on-failure",
        video: "retain-on-failure",
      },
    },
  ],
  webServer: {
    command:
      "cd .. && go run ./internal/e2eapp -addr 127.0.0.1:8443 -host localhost",
    url: "https://localhost:8443/healthz",
    ignoreHTTPSErrors: true,
    reuseExistingServer: !process.env.CI,
  },
});
