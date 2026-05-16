// =============================================================================
// Accessibility — axe-core via @axe-core/playwright
// =============================================================================
// PRD: FR-L.28 — axe-core sweep on public pages + admin console. The skeleton
// only exposes the public landing page so far; the admin sweep gets added
// when the console lands. Tagged @a11y so it can be selected in isolation
// (and is part of the nightly full run via the global config).
// =============================================================================

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.describe("@a11y public surface", () => {
  test("landing page has no critical accessibility violations", async ({ page }) => {
    await page.goto("/");
    const results = await new AxeBuilder({ page })
      // Color contrast is meaningful here; tag filtering keeps it focused on
      // the rules the WCAG AA target actually cares about.
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"])
      .analyze();

    // Provide a readable diagnostic when something regresses.
    const critical = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect.soft(critical, JSON.stringify(critical, null, 2)).toEqual([]);
  });
});
