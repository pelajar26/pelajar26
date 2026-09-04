# OpenSea Managed VDP — High/Critical Assessment

**Program:** OpenSea Managed Bug Bounty (Bugcrowd)
**Date:** 2026-09-04
**Disclosure:** Nondisclosure — internal working notes. Do NOT publish.
**Scope of this report (per user):** High / Critical only, or chains reaching High/Critical.

## Scope discipline observed
- No negative production impact; stopped probing rate-limited endpoints instead of hammering.
- Only interacted with wallets/accounts I generated and own (fresh EOAs).
- No third-party account was ever modified. All write tests targeted my own wallets.
- Prompt-injection / LLM-manipulation on the MCP surface treated as **out of scope** (excluded).
- Smart-contract state changes require forked mainnet — not performed against live contracts.
- Secrets (free-tier API key, generated private keys) kept out of this repo (redacted below).

---

## Bottom line
The tested surfaces — OAuth/OIDC, SIWE/SIWX wallet auth, the v2 REST account/wallet/agent
endpoints, and the MCP tool surface — are **robustly secured**. Every High/Critical hypothesis
I could test without on-chain funds came back negative (secure). **No High/Critical finding
confirmed.** One genuinely unusual design (cancel_order dual-auth) could not be fully tested
without a funded order and is recorded as the top residual lead.

---

## Attack surface mapped
- **REST API v2** — `api.opensea.io`, OpenAPI 3.1 spec (128 paths). Auth = `x-api-key` (`ApiKeyAuth`)
  + optional wallet JWT (`WalletAuth`, OIDC bearer) with per-endpoint scopes.
- **OAuth/OIDC IdP** — `auth.opensea.io` (ZITADEL-style). `/oauth/v2/authorize`, `/token`,
  `/oidc/v1/userinfo`, `/oauth/v2/keys`. Scopes: openid/profile/email/phone/address/offline_access.
  Public CLI client_id `379893200225068569` (loopback redirect, PKCE S256, `token_endpoint_auth=none`).
- **Wallet auth flows** — SIWE login (nonce → verify → PAT → exchange → JWT) and SIWX wallet linking.
  Message domain bound to `opensea.io`; JWT ~12h; scopes: read/write × {wallets, orders, profile,
  favorites, social}, write:drops, read:eligibility.
- **MCP server** — `mcp.opensea.io` ("OpenSea Data API" v1.0.0), SSE + streamable-HTTP. **40 tools**
  (read wrappers, `manage_*` write tools mapping to the REST endpoints, Tool Registry, `search`/`fetch`).

## High/Critical hypotheses tested → all SECURE
| # | Hypothesis (target severity) | Test | Result |
|---|---|---|---|
| 1 | OAuth **redirect_uri bypass** → code/token exfil → ATO (Crit) | authorize with foreign host, path-traversal, `@`-userinfo, subdomain-suffix, encoded traversal on client `379893200225068569` | All **400 rejected**. Only RFC-8252 loopback (127.0.0.1/localhost/::1, any port) accepted — not attacker-exploitable. **Secure** |
| 2 | OAuth **implicit flow** token leak (Crit/High) | `response_type=token` / `id_token token` | **400** — implicit disabled for this client. **Secure** |
| 3 | **SIWX signature confusion** → link victim wallet to attacker acct → ATO (Crit) | link with `message.address = B` but signature from wallet A | **400 "Invalid signature"** — server recovers signer and binds to claimed address. **Secure** |
| 4 | **Scope privilege escalation** (High) | request all/foreign scopes at PAT creation | **400 "Requested scopes exceed account entitlement"** — server-enforced; scopes only ever act on the caller's own account. **Secure** |
| 5 | **Agent-relationship unilateral bind** → act on victim's behalf (Crit) | wallet A (AGENT) proposes cp=B, then A alone calls `confirm` impersonating the OWNER side | **404 "Agent relationship not found"** — confirm is keyed to the authenticated JWT identity, not to body `caller_role`/`counterparty`. Only B's own JWT confirms. Mutual consent holds. **Secure** |
| 6 | **Cross-account wallet IDOR** (privacy toggle / unlink) (High) | wallet A (write:wallets) targets an unlinked wallet C via `PUT /accounts/wallets/{C}/private` and `DELETE /accounts/wallets/{C}` | **404 "Wallet link not found"** — ownership scoped to caller's linked wallets. **Secure** |
| 7 | **Missing-JWT read IDOR** on wallet-gated data (High) | call `favorites`, `token_watchlist` with API key but no JWT | **401 "Missing or invalid Authorization header"**. **Secure** |
| 8 | **MCP `fetch` SSRF** (Crit) | `fetch(id="https://example.com/")` and other URL forms | **Rejected** — `id` must be a structured document type (collection/item/token), not a URL. No server-side URL fetch. **Secure** |
| 9 | **MCP `get_tool` SSRF/registry abuse** (High) | arbitrary `registry_addr`, malformed `registry_chain` | Passthrough to REST with validation ("registry_chain must be numeric"). On-chain read, no SSRF. **Secure** |

## Residual leads (need funds / deeper setup — not completed)
1. **`cancel_order` maker-check IDOR** — *top lead.* `POST /orders/chain/{chain}/protocol/{addr}/{order_hash}/cancel`
   has an unusual dual security scheme: `ApiKeyAuth` **alone** (with an `offererSignature`) **or**
   `ApiKeyAuth + WalletAuth:write:orders`. If the JWT mode does not verify `order.offerer == JWT wallet`,
   any account could off-chain-cancel another user's SignedZone listings/offers → **orderbook griefing (Critical)**.
   Not confirmable without a real, funded order to test against (cancelling a stranger's live order is out
   of scope). Endpoint is also aggressively rate-limited (fulfillment 5/min → repeated 429). **Recommended
   next step:** fund a test wallet, create an off-chain listing, and verify a *second* owned account cannot
   cancel it. Only ever cancel your own orders.
2. **Solana SIWX signature path** — the EVM SIWX signer-binding is solid (#3); the Solana (`accountType=Solana`)
   verification branch is untested and may differ. Needs Solana signing (`@solana/web3.js`).
3. **Drop management authz** — `manage_drops` / `PATCH /drops/{slug}/items/{token_id}` (write:drops).
   Possible IDOR: update a drop owned by another creator. Needs an existing drop context to test safely.
4. **Wallet double-link / hijack** — could not complete: a brand-new wallet is not entitled to a
   `write:wallets`+`read:wallets` PAT combo (400 "exceed entitlement"), while a wallet with prior account
   state is. Blocked the second-account JWT needed to test whether an already-linked wallet can be
   re-linked/stolen by another account.

## Info / Low observations (not target severity — recorded for completeness)
- **Free-tier key mint is unauthenticated** (`POST /api/v2/auth/keys`, `x-ratelimit-limit: 2`). Intended
  design; low. MCP `get_instant_api_key` error verbosely passes through the upstream 429 body and the raw
  endpoint. Info.
- **Scope-entitlement inconsistency**: individual scopes are granted to a fresh wallet, but multi-scope
  PATs / certain combos require account "state" (declared agent, linked wallets). Erring restrictive
  (fewer scopes for low-trust) — not exploitable across accounts since every scope is self-account-only. Info.
- **Public agent-graph read**: `GET /accounts/{addr}/agent-relationships` is unauthenticated
  (`sec=None`) — confirmed relationships are public by design; pending ones are hidden. Info.
- Vercel deployment IDs in HTML/404; client-side Sentry DSN in JS bundles; S3 buckets return AccessDenied. Info.

## Test credentials (redacted; ephemeral)
- Free-tier API key `2150a08b…` (redacted; 7-day expiry) — minted via the documented free-tier flow.
- Generated EOAs (wallet A/B/C/X) — mine, empty, keys kept local only, not committed.
