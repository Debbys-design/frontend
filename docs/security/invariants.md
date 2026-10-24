# Security Invariants

This document records the security invariants the vault stack must uphold, the trust
boundaries between our own services, and the network surfaces each component exposes.
It is reviewed with the security preparation workstream. Client-facing rate limiting and
abuse protection, and on-chain admin key custody/KMS signing, are covered elsewhere.

## Trust boundaries and network surfaces

| Service | Externally routable | Accepts internal calls from | Outbound egress allowlist |
| --- | --- | --- | --- |
| BFF / API (`src/app/api/`) | Yes (only external entry point) | Browser clients (authenticated) | Stellar RPC, Horizon, price feeds, notification providers |
| Indexer | No | BFF/API, scheduler | Stellar RPC, Horizon |
| Scheduler | No | BFF/API | Stellar RPC, Horizon |
| Keeper | No | BFF/API, scheduler | Stellar RPC, Horizon |

- Only the BFF/API layer accepts external traffic. Indexer, scheduler, and keeper
  endpoints are not publicly routable (enforced by network policy / private networking).
- Local topology in `docker-compose.yml` mirrors these trust boundaries so development
  exercises the same isolation as production.

## Service-to-service authentication

- Every internal call is authenticated with mTLS or a short-lived signed service token
  that carries a service identity and a narrow scope claim. Handlers verify the identity
  and scope explicitly; they never trust a bare network position.
- Tokens rotate on a short interval. No shared static bearer secrets are checked into
  config; secrets are sourced from a managed store and referenced (not inlined) in
  `.env.local.example`.
- Token validation tolerates bounded clock skew, and long-running indexer/backfill jobs
  refresh tokens before expiry rather than relying on a single long-lived credential.
- Local development may run without mTLS via a documented dev bypass. The bypass cannot
  be enabled in production; production fails to boot with a missing or placeholder
  service credential.

## Least-privilege credentials per service

- The indexer cannot submit transactions.
- The keeper cannot read depositor PII it does not need.
- Each service holds only the scopes required for its role; scope claims are checked at
  the handler, not inferred from the caller's network location.

## Egress controls

- Outbound traffic is restricted to an explicit allowlist (Stellar RPC, Horizon, price
  feeds, notification providers).
- Denied-outbound calls are logged and alerted so a compromise in one service cannot
  pivot freely.

## Frontend-visible configuration

| Domain | Abbreviation | Scope |
|---|---|---|
| **signing** | `signing` | Challenge/response authentication: parsing, field validation, expiry, origin binding, nonce entropy, version gating. Covers the Freighter sign-in flow (`src/lib/auth/challengeValidator.ts`). |
| **input** | `input` | User-supplied address validation. Specifically the address-poisoning heuristic that detects look-alike wallet addresses designed to fool copy-paste. |
| **session** | `session` | Bearer token lifecycle: where tokens are stored, that logout clears them completely, and that tokens never appear in URLs. |
| **isolation** | `isolation` | Per-wallet namespacing in `localStorage`. Alert rules, workspace layouts, and anti-phishing phrases must not bleed between wallet accounts. Hotkeys (non-sensitive) are explicitly documented as intentionally global. |
| **headers** | `headers` | Structural HTTP and subresource security: `X-Frame-Options`, SRI hash format correctness, and the HTTPS-only policy for external resources. |
| **governance** | `governance` | Vault parameter and upgrade changes must flow through the timelock + multisig workflow (issue #224). No privileged setter may be reachable outside the governance path. |

- The frontend-visible subset of secrets/config is validated in `src/env.ts`; values are
  referenced from the managed store, never inlined.

## Verification

## Invariants Table

| ID | Domain | Invariant Description | Test File | Test Name | Security / WCAG Ref |
|---|---|---|---|---|---|
| SEC-001 | signing | A well-formed, unexpired challenge for the correct address and domain parses and validates without throwing. | `src/test/security/invariants.test.ts` | `SEC-001: valid challenge parses and validates without error` | SIWS §3 (happy path) |
| SEC-002 | signing | A challenge issued to address A must be rejected with `WRONG_ADDRESS` when validated against address B. | `src/test/security/invariants.test.ts` | `SEC-002: challenge for wrong address is rejected (WRONG_ADDRESS)` | SIWS §4.2; prevents session fixation |
| SEC-003 | signing | A challenge whose `Expiration Time` field is in the past must be rejected with `EXPIRED`. | `src/test/security/invariants.test.ts` | `SEC-003: expired challenge is rejected (EXPIRED)` | SIWS §4.3; prevents replay attacks |
| SEC-004 | signing | A challenge whose `URI` field does not match the expected domain must be rejected with `WRONG_DOMAIN`. | `src/test/security/invariants.test.ts` | `SEC-004: challenge with mismatched domain is rejected (WRONG_DOMAIN)` | SIWS §4.4; prevents phishing relay |
| SEC-005 | signing | A challenge with a nonce shorter than the minimum entropy threshold must be rejected with `NONCE_MALFORMED`. | `src/test/security/invariants.test.ts` | `SEC-005: malformed nonce is rejected (NONCE_MALFORMED)` | OWASP Auth §3; prevents brute-force nonce guessing |
| SEC-006 | signing | A challenge whose `URI` field is not a valid HTTPS URL must not parse (returns `null`). | `src/test/security/invariants.test.ts` | `SEC-006: challenge URI must be a valid HTTPS URL` | SIWS §4.1; OWASP Transport Layer |
| SEC-007 | signing | A challenge with a `Version` field other than `"1"` must be rejected with `VERSION_UNSUPPORTED`. | `src/test/security/invariants.test.ts` | `SEC-007: challenge version other than '1' is rejected` | SIWS §4.5; prevents downgrade attacks |
| SEC-008 | signing | A challenge whose `Issued At` timestamp is more than 10 minutes in the past must be rejected with `ISSUED_AT_TOO_OLD`. | `src/test/security/invariants.test.ts` | `SEC-008: challenge issued too far in the past is rejected (ISSUED_AT_TOO_OLD)` | SIWS §4.3; limits replay window |
| SEC-009 | signing | A challenge whose `Issued At` timestamp is more than a few minutes in the future must be rejected with `ISSUED_AT_FUTURE`. | `src/test/security/invariants.test.ts` | `SEC-009: issued-at far in the future is rejected (ISSUED_AT_FUTURE)` | SIWS §4.3; prevents clock-skew abuse |
| SEC-010 | input | An address that exactly matches a known address must not be flagged as poisoned. | `src/test/security/invariants.test.ts` | `SEC-010: exact address match is not flagged as poisoned` | CWE-20 (false-positive control) |
| SEC-011 | input | An address that matches the first N and last N characters of a known address but differs in the middle must be flagged as poisoned. | `src/test/security/invariants.test.ts` | `SEC-011: address matching first+last chars but differing in middle is flagged` | CWE-20; address-poisoning attack pattern |
| SEC-012 | input | A completely different address (no prefix/suffix match) must not be flagged as poisoned. | `src/test/security/invariants.test.ts` | `SEC-012: completely different address is not flagged` | CWE-20 (false-positive control) |
| SEC-013 | input | An empty string input must not be flagged as poisoned. | `src/test/security/invariants.test.ts` | `SEC-013: empty input is not flagged` | CWE-20; null/empty input safety |
| SEC-014 | session | After explicit logout, all `zenith.wallet.*` keys must be absent from `localStorage`. | `src/test/security/invariants.test.ts` | `SEC-014: after explicit logout, no wallet key remains in localStorage` | OWASP Session Mgmt §3.3; WCAG 2.2 SC 3.3.8 |
| SEC-015 | session | Bearer tokens must never appear as URL query parameters (detectable by scanning constructed URLs for `token=`, `auth=`, or `bearer=`). | `src/test/security/invariants.test.ts` | `SEC-015: bearer token must not appear as a URL query parameter` | OWASP ASVS V3.4.2; tokens in URLs leak via Referer/logs |
| SEC-016 | session | `sessionStorage` must be empty immediately after a fresh page load — wallet tokens are stored only in the zustand-persist `localStorage` store. | `src/test/security/invariants.test.ts` | `SEC-016: sessionStorage is empty after a fresh page load simulation` | OWASP Session Mgmt §2.1 |
| SEC-017 | isolation | Alert rules must be stored under a per-wallet key (`zenith.rules.<address>`) so that switching wallets does not expose another wallet's rules. | `src/test/security/invariants.test.ts` | `SEC-017: rules are stored per wallet address and cannot bleed across wallets` | CWE-359; data isolation |
| SEC-018 | isolation | Workspace layouts must be stored under a per-wallet key (`zenith.layout.<address>`); a different wallet must see no layout data. | `src/test/security/invariants.test.ts` | `SEC-018: workspace layouts are keyed per wallet` | CWE-359; data isolation |
| SEC-019 | isolation | Hotkeys configuration (`zenith.hotkeys.v1`) is intentionally global (non-sensitive preference) and is explicitly documented as such, not a violation. | `src/test/security/invariants.test.ts` | `SEC-019: hotkeys config is not wallet-specific (safe global preference)` | N/A — documented exception |
| SEC-020 | isolation | Anti-phishing phrases must be stored under a per-wallet key (`zenith.antiphishing.phrase.<address>`) and must not be visible to a different wallet. | `src/test/security/invariants.test.ts` | `SEC-020: anti-phishing phrase is wallet-scoped` | CWE-359; data isolation |
| SEC-021 | headers | Responses must set `X-Frame-Options: DENY` (or `SAMEORIGIN`) to prevent clickjacking. | `src/test/security/invariants.test.ts` | `SEC-021: X-Frame-Options header is set to DENY or SAMEORIGIN` | OWASP Secure Headers; WCAG 2.2 SC 2.5.8 |
| SEC-022 | headers | Every `<script>` tag with a `src` attribute must carry a valid SRI `integrity` hash in `sha256-`/`sha384-`/`sha512-` format. | `src/test/security/invariants.test.ts` | `SEC-022: external scripts carry a valid SRI integrity hash` | OWASP ASVS V14.2.3; supply-chain integrity |
| SEC-023 | headers | All external resource URLs must use `https://`; no `http://` resource may be loaded. | `src/test/security/invariants.test.ts` | `SEC-023: external resources are loaded over HTTPS only` | OWASP Transport Layer; WCAG 2.2 SC 1.4.1 |
| SEC-024 | governance | Vault parameter and upgrade changes must be submitted as typed proposals, approved by the configured multisig threshold, queued, held for the mandatory delay, and only then executed. No privileged setter (fee bps, fee recipient, capacity limits, strategy weights/parameters, oracle configuration, upgrade authorization) may be reachable outside this governance path. | `src/test/security/invariants.test.ts` | `SEC-024: privileged vault setters are unreachable outside the governance path` | Issue #224; prevents unilateral rug-pull by a single key |
| SEC-025 | governance | A proposal cannot be executed before its delay elapses or after it expires, and a consumed proposal cannot be replayed. Threshold and delay parameters themselves may only be changed through the same timelocked workflow. | `src/test/security/invariants.test.ts` | `SEC-025: timelock delay and expiry are enforced and proposals cannot be replayed` | Issue #224; timelock enforcement |

---

## Governance Workflow (Issue #224)

The vault governance module enforces the following lifecycle for every privileged change:

1. **propose** — a signer submits a typed action (fee bps, fee recipient, capacity limit, strategy weight/parameter, oracle config, or upgrade authorization). Duplicate proposals for the same parameter are rejected.
2. **approve / revoke** — signers approve up to the configured threshold; approvals may be revoked before execution.
3. **queue** — once the threshold is met, the proposal is queued and its ETA (`eta = now + delay`) is recorded.
4. **execute** — only after `eta` and before expiry; execution is one-shot (replay-protected).
5. **cancel / expire** — a queued proposal may be cancelled by governance, and stale proposals expire and can no longer execute.

Threshold and delay are stored in contract storage and may only be modified through this same workflow. Signer-set changes while proposals are pending do not retroactively validate already-queued proposals; they must be re-approved under the new set. Events are emitted for created, approved, queued, executed, cancelled, and expired stages so the indexer and operator console can surface pending/executed proposals (with ETA and approval count) read-only.

- Negative tests prove an unauthenticated or out-of-scope internal call is rejected, an
  egress-denied call is blocked and alerted, and an expired token is refused.
- A configuration test asserts production fails to boot with a missing or placeholder
  service credential.
- Auth failures are surfaced through `sentry.server.config.ts`.
