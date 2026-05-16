// =============================================================================
// Happy path — the only @happy-path-tagged spec
// =============================================================================
// PRD: FR-L.20 (happy path: user requests, opens mail, reveals password).
//
// This subset of the full flow is what ci.yml runs on every PR (FR-L.47).
// The remaining five canonical scenarios are tagged @nightly and live next to
// this file; they fill in as the reveal page lands.
//
// We exercise SealKeeper through its public HTTP surface plus the eval-only
// /__captured_mail endpoint that backs FR-H.17.
// =============================================================================

import { expect, test } from "@playwright/test";

test.describe("@happy-path public flow", () => {
  test("landing page advertises the available routes in eval mode", async ({ page }) => {
    const response = await page.goto("/");
    expect(response?.status()).toBe(200);
    await expect(page).toHaveTitle(/SealKeeper/);

    // FR-H.13 — eval mode shows an unmistakable banner.
    await expect(page.getByText(/Evaluation mode/i)).toBeVisible();

    // Operator-facing endpoints are linked from the stub landing page.
    for (const path of ["/healthz", "/readyz", "/metrics", "/api/v1/policy", "/version"]) {
      await expect(page.locator(`a[href="${path}"]`)).toBeVisible();
    }
  });

  test("policy endpoint returns the v0.1 default JSON", async ({ request }) => {
    const r = await request.get("/api/v1/policy");
    expect(r.status()).toBe(200);
    expect(r.headers()["content-type"]).toMatch(/application\/json/);

    const body = await r.json();
    expect(body).toMatchObject({
      version: 1,
      generators: expect.arrayContaining(["G1", "G2", "G3"]),
      min_entropy_bits: 80,
      levels: expect.arrayContaining(["standard", "high", "very_high"]),
      transforms: expect.arrayContaining(["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"]),
    });
  });

  test("user request is accepted and the mail is captured in eval mode", async ({ request }) => {
    const email = `happy+${Date.now()}@example.test`;
    const accept = await request.post("/api/v1/request", {
      data: { email, domain: "example.test", subject: "smoke" },
      headers: { "Content-Type": "application/json" },
    });
    expect(accept.status()).toBe(202);

    const accepted = await accept.json();
    expect(accepted).toMatchObject({ status: "accepted" });
    expect(typeof accepted.capture).toBe("string");

    // The eval-only mail capture endpoint MUST surface the new entry.
    const mailbox = await request.get("/__captured_mail");
    expect(mailbox.status()).toBe(200);
    const { items } = (await mailbox.json()) as { items: Array<{ to: string; subject: string }> };
    expect(items.some((m) => m.to === email)).toBe(true);
  });

  test("readiness and liveness endpoints behave per FR-D.49 / FR-D.50", async ({ request }) => {
    const live = await request.get("/healthz");
    expect(live.status()).toBe(200);
    expect((await live.json()).status).toBe("ok");

    const ready = await request.get("/readyz");
    expect(ready.status()).toBe(200);
    const readyBody = await ready.json();
    expect(readyBody.status).toBe("ok");
    expect(readyBody.subsystems).toBeDefined();
  });
});
