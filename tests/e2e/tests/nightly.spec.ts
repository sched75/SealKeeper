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
  // FR-L.21 — promoted to @happy-path: rate-limit behaviour covered in
  // happy-path.spec.ts ("rate-limited request stays silent (FR-B.13)").

  // FR-L.22 — domain allowlist gate ships with the admin domains layer.
  // End-to-end coverage lives in internal/domains_test.go (matcher logic) +
  // the @happy-path silent-drop semantics (FR-B.13). A full UI walk-through
  // through /admin/domains lands once the admin login E2E (FR-L.25) does.

  test.fixme("@nightly expired reveal link returns the 'expired' error page", async () => {
    // FR-L.23 — depends on the reveal-page route and token TTL handling.
  });

  // FR-L.24 — promoted to @happy-path: single-use semantics covered in
  // happy-path.spec.ts ("token is single-use (second consumption returns 410)").

  test.fixme("@nightly admin can sign in with password + TOTP", async () => {
    // FR-L.25 — depends on the admin console (module C) and TOTP provider.
  });

  test.fixme("@nightly admin can revoke an active user session", async () => {
    // FR-L.26 — depends on the admin sessions UI.
  });
});
