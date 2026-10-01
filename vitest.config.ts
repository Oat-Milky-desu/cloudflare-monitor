import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // The bundled workerd runtime currently supports compatibility dates only
        // through 2026-08-22; production keeps the project's Wrangler date.
        compatibilityDate: "2026-08-22",
        bindings: {
          ADMIN_USERNAME: "admin",
          ADMIN_PASSWORD: "test-password-at-least-12",
        },
      },
    }),
  ],
  test: {
    include: ["tests/**/*.test.ts"],
  },
});
