# SealKeeper — End-to-end suite

Playwright tests covering the public flow, plus an axe-core a11y sweep.
PRD reference: module L §3.3 (FR-L.19..30).

## Run locally

Prereqs:

- Node ≥ 20
- Go ≥ 1.22 (the config falls back to `go run` when `SEALKEEPER_BIN` is unset)
- Playwright browsers installed once: `npx playwright install --with-deps`

```bash
cd tests/e2e
npm ci

# Happy path only, Chromium — same as the CI subset on PRs.
npm run test:happy

# Full nightly grep — currently the @nightly specs are scaffolded with
# test.fixme(...) so they show as "expected to fail" until the underlying
# backend feature lands.
npm run test:nightly

# Accessibility (axe-core) check on the public surface.
npm run test:a11y

# Everything, all three browsers — what nightly.yml runs.
npm test
```

To inspect a failed run:

```bash
npm run report
```

## Run against a pre-built binary

The CI release pipeline builds `dist/sealkeeper-linux-amd64`, then sets
`SEALKEEPER_BIN` so Playwright starts that exact artifact rather than `go run`:

```bash
make build
SEALKEEPER_BIN="$(pwd)/dist/sealkeeper" npm test
```

## Tag scheme

| Tag             | Used by                              |
|-----------------|--------------------------------------|
| `@happy-path`   | ci.yml on every PR (Chromium only)   |
| `@nightly`      | nightly.yml — full canonical suite   |
| `@a11y`         | a11y check (axe-core)                |

A test can carry multiple tags by mentioning them in `describe` / `test` titles.

## Scenarios

| File                 | FR     | Status                                  |
|----------------------|--------|-----------------------------------------|
| `happy-path.spec.ts` | L.20   | implemented against the v0.1 skeleton   |
| `nightly.spec.ts`    | L.21-26| scaffolded as `test.fixme` placeholders |
| `a11y.spec.ts`       | L.28   | implemented on the landing page         |

## Notes

- The `webServer` block in `playwright.config.ts` boots SealKeeper in
  `eval` mode so the SMTP capture queue (`/__captured_mail`) is available.
- A single backend instance is shared between tests (`fullyParallel: false`,
  `workers: 1`) so the mailbox state can be inspected deterministically.
- HTML reports + traces + videos are kept for failures only and uploaded
  by ci.yml / nightly.yml on red builds.
