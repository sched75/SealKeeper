// =============================================================================
// Nightly scenarios — placeholders for the remaining canonical flows
// =============================================================================
// PRD: FR-L.21..26 (rate-limit, domain block, expired link, double
// consumption, admin TOTP login) — these all depend on backend features that
// land after the skeleton.
//
// Each test below is tagged @nightly so the nightly workflow picks it up.
// They are skipped via `test.fixme` until their underlying feature lands —
// that way the spec is visible to maintainers (and shows up in the report as
// "fixme") instead of vanishing.
// =============================================================================

import { test } from "@playwright/test";

test.describe("@nightly canonical scenarios", () => {
  test.fixme("@nightly rate-limit blocks repeat requests from the same domain", async () => {
    // FR-L.21 — once the per-domain rate limiter (module D) lands, exercise it
    // here: send the policy-allowed number of POST /api/v1/request and assert
    // the next one returns 429 with a Problem Details body.
  });

  test.fixme("@nightly explicitly blocked domain returns 403 without revealing the policy", async () => {
    // FR-L.22 — depends on the admin console publishing a blocked-domains list
    // through the policy descriptor.
  });

  test.fixme("@nightly expired reveal link returns the 'expired' error page", async () => {
    // FR-L.23 — depends on the reveal-page route and token TTL handling.
  });

  test.fixme("@nightly a reveal link cannot be consumed twice", async () => {
    // FR-L.24 — token consumption logic + session store land in module D.
  });

  test.fixme("@nightly admin can sign in with password + TOTP", async () => {
    // FR-L.25 — depends on the admin console (module C) and TOTP provider.
  });

  test.fixme("@nightly admin can revoke an active user session", async () => {
    // FR-L.26 — depends on the admin sessions UI.
  });
});
