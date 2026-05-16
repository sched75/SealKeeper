// =============================================================================
// SealKeeper — Vitest configuration
// =============================================================================
// PRD: FR-L.17 — JS coverage MUST be ≥ 90% on the generator. Thresholds below
// are hard-enforced so the CI job in ci.yml fails on regression.
// =============================================================================

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    include: ["tests/**/*.test.js"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "json-summary", "html"],
      include: ["src/**/*.js"],
      exclude: ["src/index.js", "src/data/**"],
      thresholds: {
        // FR-L.17 — applies to the generator surface, not data.
        lines: 90,
        statements: 90,
        functions: 90,
        branches: 85,
      },
    },
  },
});
