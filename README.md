# auth-service

User registration, login (email **or** phone + password) and password reset by emailed code.
Built with Node.js, Express 5 and TypeScript. It stores data in **MongoDB or PostgreSQL**, chosen with
`DB_DRIVER`, and sends Gmail via OAuth2. Backend only; it runs as a separate service next to the
Call Blocker app.

**Database:** set `DB_DRIVER=mongodb` (uses `MONGODB_URI`) or `DB_DRIVER=postgres` (uses `DATABASE_URL`; tables are
created automatically). Both drivers have identical behaviour and pass the same tests.
Details: [docs/DATABASE_DRIVERS.md](docs/DATABASE_DRIVERS.md).

**Multi-tenant:** every app or website is a tenant identified by its API key. Each tenant's users, sessions and
reset codes live in their own collections/tables (`<tenant>_users`, …) or, optionally, their own
database (MongoDB) or schema (PostgreSQL).
Full design, security analysis and runbooks: [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md).

**Subscriptions:** 6 months $10 / 1 year $15 / Lifetime $20 via Google Play, verified server-side; entitlement status
with a per-tenant sync interval (stored in the database, set by an admin API); rule backup/sync for the app.
Details: [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md).

## Quick start

```bash
cp .env.example .env              # set DB_DRIVER + its URL and the two secrets; MAIL_TRANSPORT=console prints codes
cp tenants.example.json tenants.json
npm run tenant:key -- callblocker_android   # put the printed hash in tenants.json, give the key to the app
npm install
npm run dev                       # needs MongoDB (MONGODB_URI) or PostgreSQL (DATABASE_URL)
# or the full stack (pick the profile that matches DB_DRIVER):
docker compose --profile mongodb up --build
docker compose --profile postgres up --build
npm test                          # 156 end-to-end tests: every suite on real MongoDB AND real PostgreSQL
npm run build && npm start        # production build
```

## API (`/api/v1/auth`)

All requests and responses are JSON. Errors always look like:
`{ "error": { "code", "message", "details"?: [{ "field", "message" }], "requestId" } }`.
Every `/api` call needs the tenant's **`X-API-Key`** header (optionally `X-Tenant-Id`, which must match).
An unknown key returns `401`. A tenant mismatch, a disabled tenant, or a browser origin not allowed for the tenant returns `403`.

| Method | Path | Body | Success |
|---|---|---|---|
| POST | `/register` | `fullName, email, country, phone, password, confirmPassword` | `201 { user, tokens }` |
| POST | `/login` | `email, password` **or** `phone, password` (+ `country` for national numbers) | `200 { user, tokens }` |
| POST | `/refresh` | `refreshToken` | `200 { tokens }` (old refresh token is consumed) |
| POST | `/logout` | `refreshToken` | `204` |
| POST | `/logout-all` | — (Bearer) | `204`, signs out every device |
| GET | `/me` | — (Bearer) | `200 { user }` |
| POST | `/forgot-password` | `email` | `202` (always, even for unknown emails) |
| POST | `/reset-password` | `email, code, newPassword, confirmPassword` | `200` |
| POST | `/change-password` | `currentPassword, newPassword, confirmPassword` (Bearer) | `200 { tokens }` |

Subscriptions & sync (see [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md)):

| Method | Path | Body | Success |
|---|---|---|---|
| GET | `/api/v1/subscriptions/plans` | — | `200 { plans, providers }` |
| GET | `/api/v1/subscriptions/me` | — (Bearer) | `200 { subscription, sync: { interval, intervalSeconds }, accountToken, serverTime }` |
| POST | `/api/v1/subscriptions/purchase` | `planId, provider, purchaseToken` (Bearer) | `200` same as `/me` |
| GET/POST | `/api/v1/sync/rules` | `mode: merge\|replace, rules[]` (Bearer) | `200 { rules, updatedAt }` |
| GET/PUT | `/api/v1/admin/subscription-sync-interval` | `{ value, unit: minute\|hour\|day\|month\|year }` (`X-Admin-Key`) | `200 { interval, intervalSeconds }` |

`country` is an ISO code (`"US"`). `phone` can be national (`"(415) 555-0123"`) or international
(`"+14155550123"`); it is stored as E.164. Passwords must be **at least 8 characters**
(max 128). A shorter one returns `400` with
`{ "field": "password", "message": "Password must be at least 8 characters long" }`.

`tokens` = `{ tokenType: "Bearer", accessToken, accessTokenExpiresIn, refreshToken, refreshTokenExpiresAt }`.
Send `Authorization: Bearer <accessToken>`. When it expires (15 min), call `/refresh`.

Status codes: `400` validation · `401` bad credentials/token · `409` email or phone already
registered · `413` body too large · `415` not JSON · `423` account locked · `429` rate limited.

### Forgot-password flow

1. `POST /forgot-password { email }` emails a 6-digit code (valid 15 min, single use, 5 attempts).
2. `POST /reset-password { email, code, newPassword, confirmPassword }` sets the new password.
   All sessions are revoked and a "password changed" email is sent.

## Gmail sending with Google Cloud OAuth2

1. In [Google Cloud Console](https://console.cloud.google.com/), create a project and enable the
   **Gmail API**.
2. **APIs & Services → OAuth consent screen**: configure it and add your sending Gmail address as a
   test user (or publish the app).
3. **Credentials → Create credentials → OAuth client ID**: choose type *Web application* and add
   `https://developers.google.com/oauthplayground` as an authorized redirect URI. Copy the
   **Client ID** and **Client secret**.
4. Open the [OAuth 2.0 Playground](https://developers.google.com/oauthplayground). Under ⚙ settings,
   tick *Use your own OAuth credentials* and paste the id and secret. Authorize scope
   `https://mail.google.com/` while signed in as the sending account, then *Exchange authorization
   code for tokens*. Copy the **Refresh token**.
5. Set in `.env`:
   ```
   MAIL_TRANSPORT=gmail
   GMAIL_USER=sender@gmail.com
   GOOGLE_CLIENT_ID=...apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=...
   GOOGLE_REFRESH_TOKEN=...
   ```
   Nodemailer exchanges the refresh token for access tokens and renews them automatically. On
   startup the service verifies the connection and logs `mail transport ready` (or the error).

> While the consent screen is in *Testing*, Google expires refresh tokens after 7 days. Publish
> the app (or use a Google Workspace internal app) for a long-lived token.

## Security measures

- **Passwords**: Argon2id one-way hashes with a per-password salt (OWASP parameters), upgraded
  automatically on login if the parameters change. They are never stored in plain or reversible
  form and never logged.
- **Credential attacks**: generic "Invalid credentials" errors. A dummy hash check runs for unknown
  accounts, so timing doesn't reveal them. Accounts lock for 15 min after 5 failures. Rate limits
  apply per IP and per IP + account.
- **Tokens**: short-lived HS256 JWTs (pinned algorithm, issuer, audience). A per-user `tokenVersion`
  instantly invalidates access tokens after a password reset or logout-all. Refresh tokens are
  opaque, stored only as SHA-256 hashes, rotated on every use, and **reuse detection** revokes the
  whole token family.
- **Reset codes**: generated with `crypto.randomInt`, stored only as an HMAC-SHA256 with a server
  secret, expire automatically (MongoDB TTL index, or a scheduled purge in PostgreSQL; expired codes are
  ignored by every query either way), and allow at most 5 attempts (counted atomically). Responses don't reveal whether an email exists. Resends have a cooldown.
- **Input**: strict Zod schemas reject unknown fields (no mass assignment) and non-string values.
  MongoDB: `sanitizeFilter` blocks operator injection. PostgreSQL: parameterised queries only, and
  identifiers come from validated tenant ids and are quoted. JSON-only bodies are capped at 10 kB.
- **HTTP**: Helmet security headers, CORS allow-list, `Cache-Control: no-store` on API responses,
  `x-powered-by` removed, request IDs, and a per-tenant `X-API-Key` on every API call.
- **Operations**: configuration is validated at startup (weak or missing secrets refuse to boot;
  production requires Gmail), logs redact passwords, tokens and codes, there are health checks, and
  shutdown is graceful. The Docker image runs as a non-root user.
- **Tenant isolation**: the tenant is resolved from the hashed API key (never from client claims).
  There are no global models; every query uses the tenant's own collections or tables. JWTs are bound to the
  tenant (`tid` + audience), reset codes are tenant-scoped, and browser origins are allow-listed per tenant.

## Structure

```
src/config/env.ts                  validated configuration
src/app.ts                         Express app (security middleware, routes, errors)
src/server.ts                      bootstrap + graceful shutdown
src/container.ts                   composition root (storage, mailer, tenants)
src/middleware/                    validation, tenant resolution, auth, rate limits, error handler
src/modules/auth/                  schemas, AuthService (use-cases), TokenService, PasswordService
src/modules/mail/                  Mailer port, GmailMailer (OAuth2), console/memory mailers, templates
src/modules/users/user.ts          public user shape
src/modules/subscriptions/         plans, sync interval, SubscriptionService, Google Play + sandbox verifiers, routes
src/modules/sync/                  rule backup/sync API (merge / replace)
src/persistence/types.ts           repository + StorageProvider ports (storage-agnostic)
src/persistence/mongo/             MongoDB implementation (Mongoose, per-tenant models, TTL indexes)
src/persistence/postgres/          PostgreSQL implementation (node-postgres, per-tenant DDL, SQL repositories)
src/persistence/index.ts           createStorage(): picks the driver from DB_DRIVER
src/tenancy/                       tenant config loader, registry (API key → tenant)
scripts/                           tenant:key (onboarding), tenant:migrate (legacy Mongo data → tenant)
docs/MULTI_TENANCY.md              multi-tenancy design & implementation plan
docs/DATABASE_DRIVERS.md           MongoDB vs PostgreSQL setup, schema, parity, operations
docs/SUBSCRIPTIONS.md              plans, purchase verification, sync interval, rule sync, Play Console setup
tests/                             supertest suites run on both drivers + storage contract tests
```
