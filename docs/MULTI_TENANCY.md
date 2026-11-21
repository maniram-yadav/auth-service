# Multi-Tenancy: Design & Implementation Plan

**Service:** `auth-service` (Node.js · Express 5 · TypeScript · MongoDB/Mongoose)
**Status:** Implemented. 47 automated tests, including 13 for tenancy, plus a live smoke test against MongoDB.

---

## 1. Goal & Requirements

Users register and sign in from several **client applications**, such as the Call Blocker Android app, a
marketing website, or a partner portal. Each client is a **tenant**. Its users, sessions and password-reset
data must be stored **separately**, based on where the request comes from.

| # | Requirement | How it is met |
|---|-------------|---------------|
| T1 | Identify which app or website sent each request | Per-tenant **API key** (`X-API-Key`), resolved server-side |
| T2 | Store registration and login data in **separate collections per tenant** | `<tenant>_users`, `<tenant>_refresh_tokens`, `<tenant>_password_resets` |
| T3 | The same person can register independently in different tenants | Uniqueness of email and phone is enforced **within** a tenant only |
| T4 | Credentials, tokens and reset codes must never work across tenants | Tenant-bound JWT (`tid` + audience), tenant collections, tenant-scoped HMAC |
| T5 | Per-tenant behaviour (allowed browser origins, email branding, enable/disable) | Tenant configuration file |
| T6 | All existing security guarantees remain | Unchanged pipeline; tenant gate added in front |
| T7 | Easy onboarding of new tenants and migration of existing data | `npm run tenant:key`, `npm run tenant:migrate` |

---

## 2. Key Design Decisions

### 2.1 How the tenant is identified

| Option | Verdict | Why |
|--------|---------|-----|
| `X-Tenant-Id` header only | ❌ Rejected | Any caller can claim any tenant |
| `Origin` / `Host` header | ❌ Not sufficient alone | Mobile apps and servers send no Origin, and non-browser clients can forge it |
| Sub-domain per tenant (`shop.auth.example.com`) | Possible later | Needs DNS and TLS per tenant; doesn't fit mobile apps well |
| **Per-tenant API key** (`X-API-Key`) | ✅ **Chosen** | Works for every client type, can be rotated, and is resolved and verified server-side |

**Rules implemented in `resolveTenant` (src/middleware/security.ts):**
1. The `X-API-Key` header is required on every `/api` request. The service looks up the **SHA-256 of the
   key** and never stores or compares plaintext keys.
2. An optional `X-Tenant-Id` header, if sent, **must match** the tenant of the key (403 otherwise).
   This guards against clients misconfigured with the wrong key.
3. If the request has an `Origin` header (a browser), it must be one of **that tenant's**
   `allowedOrigins` (403 otherwise). A website can't use the mobile app's key from a browser.
4. Disabled tenants get 403. Their data is kept.
5. On success the request carries `req.tenant = { id, config, models }`. Nothing downstream
   reads tenant information from client input again.

> **Honest note on API keys in public clients:** a key shipped inside a mobile app or a web page
> can be extracted. For public clients the key is an **identifier with abuse controls**, not a strong
> secret. Account security still rests on user passwords, lockout, rate limits and tenant-bound
> tokens. The origin allow-list stops other websites from using a tenant's key from a browser. For
> confidential server-to-server clients the key *is* a secret and should be stored as one.

### 2.2 How tenant data is isolated

| Strategy | Layout | Pros | Cons |
|----------|--------|------|------|
| Shared collection + `tenantId` field | `users { tenantId, … }` | Few collections | One missing filter leaks data; doesn't meet "separate collections" (T2) |
| **Collection per tenant** (default) | `mobile_app_users`, `web_portal_users`, … in one DB | Meets T2; isolation enforced by the model a request is bound to; simple backups | Collection count grows ×3 per tenant |
| **Database per tenant** (supported) | DB `auth_mobile_app` → `users`, … | Strongest isolation; per-tenant backup, restore and drop; per-DB access control possible | More databases to monitor |

Both strategies are implemented behind one switch (`TENANT_ISOLATION=collection|database`). The rest
of the code is identical, because services only ever use `tenant.models.*`.

**Why the isolation is structural:** there is **no global `User` model** any more. Schemas are exported,
and `TenantModelFactory` binds them to a tenant's collection or database. A query can't "forget"
a tenant filter, because the model itself belongs to one tenant.

### 2.3 Naming

- Tenant id: `^[a-z][a-z0-9_]{1,31}$` (validated at startup). This keeps collection and database names
  safe and readable.
- Collection strategy: `<tenantId>_users`, `<tenantId>_refresh_tokens`, `<tenantId>_password_resets`.
- Database strategy: database `<TENANT_DB_PREFIX><tenantId>` with collections `users`, `refresh_tokens`, `password_resets`.
- Mongoose model names are `<tenantId>:User` etc. on the shared connection, so they stay unique per connection.

### 2.4 Where tenants are configured

Tenants are loaded at startup from **`TENANTS_FILE`** (a JSON file) or **`TENANTS_JSON`** (inline, e.g. from a
secret manager) and validated with Zod. The service refuses to boot on invalid ids, non-hash keys,
duplicate ids, or one key shared by two tenants.

Why a file instead of a database collection: there is no admin surface to secure, changes go through review,
and it is fast in-memory. Moving to a DB-backed tenant registry with an admin API is listed in §10.

---

## 3. Architecture

```
Client (Android app / website / partner server)
   │  X-API-Key: tk_…   [Origin: https://…]   [Authorization: Bearer …]
   ▼
┌─────────────────────────────── auth-service ───────────────────────────────┐
│ pino-http (request id) → helmet → CORS (env + all tenants' origins)        │
│ → global IP rate limit                                                     │
│ /health/*  (no tenant)                                                     │
│ /api → noStore → resolveTenant ──► TenantRegistry (sha256(key) → config)    │
│                     │                    └─► TenantModelFactory.get(id)    │
│                     ▼                          (models + indexes, cached)  │
│        req.tenant = { id, config, models }                                 │
│ → JSON-only → body parser (10 kB) → per-tenant rate limits → Zod validation │
│ → AuthService(tenant, …) / TokenService(tenant, …) / requireAuth(tenant)    │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    ▼
        MongoDB  ─ collection strategy ─  mobile_app_users | web_portal_users | …
                 ─ database strategy  ─  auth_mobile_app.users | auth_web_portal.users
```

### 3.1 Components

| File | Responsibility |
|------|----------------|
| `src/tenancy/tenant.ts` | `TenantConfig` schema, tenant id rules, `loadTenantConfigs()` (file or inline JSON) |
| `src/tenancy/tenant-registry.ts` | In-memory index by id and by API-key hash; `context()` builds a `TenantContext` |
| `src/tenancy/tenant-models.ts` | `TenantModelFactory`: binds schemas to per-tenant collections/DBs, creates indexes once, caches; `physicalNames()` |
| `src/middleware/security.ts` | `resolveTenant`, tenant-aware `requireAuth`, tenant-scoped rate-limit keys |
| `src/modules/auth/auth.service.ts` | Every use case takes `TenantContext` as its first argument |
| `src/modules/auth/token.service.ts` | Tenant-bound JWTs (`tid` claim, audience `<JWT_AUDIENCE>:<tenant>`), refresh tokens in the tenant collection |
| `scripts/create-tenant-key.ts` | Generates a key and its hash for onboarding |
| `scripts/migrate-legacy-to-tenant.ts` | Moves single-tenant collections into a tenant (dry run by default) |

### 3.2 Request lifecycle (login example)

1. `POST /api/v1/auth/login` with `X-API-Key: tk_web_portal_…`, `Origin: https://portal.example.com`.
2. CORS: the origin is in the union of tenant origins, so the response headers allow it.
3. `resolveTenant`: `sha256(key)` maps to `web_portal`. No conflicting `X-Tenant-Id`. Tenant enabled. Origin is in
   `web_portal.allowedOrigins`. Then `req.tenant` is set. The first request for a tenant awaits its index build.
4. The rate limiter keys on `web_portal|<ip>|<email>`.
5. `AuthService.login(tenant, …)` queries `tenant.models.users` (`web_portal_users`).
6. Tokens: the JWT gets `tid=web_portal` and `aud=call-blocker-app:web_portal`. The refresh token hash is stored in
   `web_portal_refresh_tokens`.

---

## 4. Data Model (per tenant)

The schemas are unchanged from the single-tenant version. Only their physical location changes.

| Collection | Key fields | Indexes |
|------------|-----------|---------|
| `<t>_users` | fullName, email, country, phone (E.164), passwordHash (Argon2id), tokenVersion, failedLoginAttempts, lockUntil | unique `email`, unique `phone` (**per tenant**) |
| `<t>_refresh_tokens` | userId, tokenHash (SHA-256), family, expiresAt, revokedAt, replacedByHash | unique `tokenHash`, `userId`, `family`, TTL on `expiresAt` |
| `<t>_password_resets` | userId, codeHash (HMAC), attempts, expiresAt | unique `userId`, TTL on `expiresAt` |

The API now returns `user.tenant` alongside `user.id`.

---

## 5. Security Analysis (tenant-specific)

| Threat | Mitigation | Test |
|--------|------------|------|
| Caller claims another tenant via header | Tenant comes only from the API key; `X-Tenant-Id` must agree | `rejects an X-Tenant-Id that disagrees…` |
| Unknown or revoked client | No matching key hash → 401; `enabled:false` → 403 | `rejects requests without a valid tenant API key`, `rejects disabled tenants` |
| Website A uses tenant B's key in a browser | Per-tenant origin allow-list → 403 | `only accepts browser requests from the tenant's own origins` |
| Access token replayed on another tenant | JWT audience **and** `tid` must equal the request's tenant; user looked up in the tenant collection | `rejects one tenant's access token on another tenant` |
| Refresh token replayed on another tenant | Lookup only in the tenant's collection; the failed attempt doesn't consume it | `rejects one tenant's refresh token on another tenant` |
| Reset code from tenant A used on tenant B | HMAC input is `"<tenant>:<code>"`; the reset record lives in the tenant collection | `scopes password reset codes to the tenant…` |
| Data leak through a forgotten tenant filter | No global models; every model is bound to one tenant | `stores each tenant in its own collections` |
| One tenant exhausts another's rate limits | Credential limiter keys include the tenant id | covered by limiter key design |
| Collection-name injection | Tenant id regex enforced at config load and in the factory | `validates ids, key hashes and duplicates` |
| Leaked config file | Only SHA-256 hashes of keys are stored; `tenants.json` is git-ignored | — |

All earlier controls still apply: Argon2id, lockout, generic errors, refresh rotation with reuse detection,
`sanitizeFilter`, strict schemas, Helmet, no-store, request IDs and log redaction.

---

## 6. Configuration Reference

### 6.1 Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `TENANTS_FILE` | — | Path to `tenants.json` (required unless `TENANTS_JSON` is set) |
| `TENANTS_JSON` | — | Inline JSON with the same shape; takes precedence |
| `TENANT_ISOLATION` | `collection` | `collection` or `database` |
| `TENANT_DB_PREFIX` | `auth_` | Database name prefix for the `database` strategy |
| `CORS_ORIGINS` | — | Extra origins; tenant origins are added automatically |
| ~~`API_KEYS`~~ | — | **Removed.** Superseded by per-tenant keys |

### 6.2 `tenants.json`

```json
{
  "tenants": [
    {
      "id": "callblocker_android",
      "name": "Call Blocker Android app",
      "apiKeyHashes": ["<sha256 of key>"],
      "allowedOrigins": [],
      "enabled": true,
      "mail": { "appName": "Call Blocker" }
    },
    {
      "id": "marketing_web",
      "name": "Marketing website",
      "apiKeyHashes": ["<sha256 of current key>", "<sha256 of next key>"],
      "allowedOrigins": ["https://www.example.com"],
      "mail": { "appName": "Example", "from": "Example <no-reply@example.com>" }
    }
  ]
}
```

- `apiKeyHashes` takes several entries, which allows zero-downtime **key rotation**: add the new hash, deploy,
  switch the client, then remove the old hash.
- `mail.from` must be the Gmail account or one of its verified "Send mail as" aliases.

---

## 7. API Changes

| Before | After |
|--------|-------|
| `X-API-Key` optional (global `API_KEYS`) | `X-API-Key` **required**; it selects the tenant |
| — | Optional `X-Tenant-Id` (must match the key) |
| `user` object | `user.tenant` added |
| JWT `aud = JWT_AUDIENCE` | JWT `aud = JWT_AUDIENCE:<tenant>`, plus `tid` claim |
| — | New errors: `401` unknown key, `403` tenant mismatch / disabled / origin not allowed |

Endpoints, request bodies and the other responses are unchanged.

Example:
```bash
curl -X POST https://auth.example.com/api/v1/auth/register \
  -H "Content-Type: application/json" -H "X-API-Key: tk_marketing_web_…" \
  -d '{"fullName":"Sam Lee","email":"sam@example.com","country":"US","phone":"2125550147",
       "password":"S3cure pass!","confirmPassword":"S3cure pass!"}'
```

---

## 8. Implementation Plan (as executed)

| Phase | Tasks | Status |
|-------|-------|--------|
| **1. Tenant model** | `TenantConfig` schema and loader; id rules; duplicate key/id detection; env vars | ✅ |
| **2. Data isolation** | Convert global models to exported schemas; `TenantModelFactory` (collection + database strategies, lazy cached index init); `TenantRegistry` | ✅ |
| **3. Request pipeline** | `resolveTenant` (key → tenant, header check, origin check, enabled); CORS union; tenant-aware `requireAuth`; tenant-scoped limiter keys; `req.tenant` typing | ✅ |
| **4. Use cases** | `AuthService` and `TokenService` take `TenantContext`; tenant-bound JWT; tenant-scoped reset HMAC; per-tenant mail branding (`appName`, `from`) | ✅ |
| **5. Bootstrap** | Container wires the registry; server pre-creates every tenant's collections and indexes and logs `tenants ready` | ✅ |
| **6. Tooling** | `npm run tenant:key`, `npm run tenant:migrate` (dry run / `--apply`, refuses to overwrite); `tenants.example.json`; compose mount | ✅ |
| **7. Tests** | Tenancy suite (resolution, isolation, cross-tenant tokens and codes, database strategy, config validation); existing suites ported | ✅ 47/47 |
| **8. Verification** | Live run: 2 tenants, same email registered in both, cross-tenant token rejected, foreign origin rejected, 6 physical collections | ✅ |

---

## 9. Runbooks

### 9.1 Onboard a new app or website
1. Choose an id, e.g. `partner_portal`.
2. `npm run tenant:key -- partner_portal`. Give the **key** to the client team through a secure channel.
3. Add an entry to `tenants.json` with the printed **hash**, plus `allowedOrigins` for browser clients and
   optional `mail` branding.
4. Deploy or restart. Startup logs `tenants ready` with the new id, and its collections and indexes are created.
5. The client sends `X-API-Key` on every request. Browser clients must call from an allowed origin.

### 9.2 Rotate a tenant's key
Add the new hash next to the old one, deploy, switch the client to the new key, then remove the old hash and deploy.

### 9.3 Disable a tenant
Set `"enabled": false` and deploy. Requests get 403 and the data is kept. Re-enable at any time.

### 9.4 Delete a tenant's data
Collection strategy: drop `<id>_users`, `<id>_refresh_tokens` and `<id>_password_resets`. Database strategy: drop
`<prefix><id>`. Then remove the tenant entry. Take a backup first.

### 9.5 Migrate the existing single-tenant data
The previous version stored data in `users`, `refreshtokens` and `passwordresets`.
```bash
MONGODB_URI=... npm run tenant:migrate -- callblocker_android          # dry run
MONGODB_URI=... npm run tenant:migrate -- callblocker_android --apply  # rename
```
This uses `renameCollection`, which is fast and keeps documents and indexes. It refuses to overwrite existing
targets. After migrating, old **access tokens** are rejected because they have no tenant claim. Clients
call `/refresh` or sign in again. Refresh tokens keep working.

### 9.6 Switch isolation strategy
Changing `TENANT_ISOLATION` on a deployed system needs a data move: for each tenant, export
`<id>_*` and import it into `<prefix><id>.*` (or the reverse). Pick the strategy before go-live.

---

## 10. Operations & Scaling Notes

- **Collection count:** 3 collections and ~8 indexes per tenant. This is comfortable for hundreds of tenants.
  For thousands, prefer the `database` strategy or a sharded cluster, and watch WiredTiger file handles.
- **Index creation:** done at startup for all configured tenants, and lazily, once, for any tenant
  first seen at runtime. Failures aren't cached, so the next request retries.
- **Backups:** the `database` strategy lets you back up and restore a single tenant.
- **Observability:** logs include `tenant` for registration, lockout, reset and mail errors. Add a
  `tenant` label to request metrics when a metrics stack is introduced.
- **Configuration changes:** require a restart (or rolling deploy). This is a deliberate choice for auditability.

### Future enhancements
1. A DB-backed tenant registry with an authenticated admin API and hot reload.
2. Per-tenant policies: password rules, token TTLs, lockout thresholds and rate limits.
3. Per-tenant mail transports or credentials, for different Google Workspace senders.
4. Per-tenant JWT signing keys (RS256 with JWKS), so tenants can verify tokens themselves.
5. Sub-domain based tenant resolution for white-label websites.
6. Tenant-level audit log collection (`<t>_audit_events`).

---

## 11. Testing Strategy

| Suite | Focus |
|-------|-------|
| `tests/auth.test.ts` | Registration, login (email or phone), lockout, tokens, forgot/reset/change password, within one tenant |
| `tests/security.test.ts` | Headers, no-store, CORS (env + tenant origins), rate limiting, body limits, config validation |
| `tests/tenancy.test.ts` | Key resolution, header mismatch, disabled tenants, per-tenant origins, physical collection separation, same email in two tenants, cross-tenant access, refresh and reset rejection, mail branding, database strategy, config validation |

Run `npm test`. Tests use a real MongoDB through `mongodb-memory-server`.
