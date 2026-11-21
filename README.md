# auth-service

User registration, login (email **or** phone + password) and password reset by emailed code.
Built with Node.js, Express 5, TypeScript, MongoDB (Mongoose) and Gmail sending via OAuth2.
Backend only; it runs as a separate service next to the Call Blocker app.

**Multi-tenant:** every app or website is a tenant identified by its API key. Each tenant's users, sessions and
reset codes live in their own collections (`<tenant>_users`, …) or, optionally, their own database.
Full design, security analysis and runbooks: [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md).

## Quick start

```bash
cp .env.example .env              # set the two secrets; MAIL_TRANSPORT=console prints codes to the log
cp tenants.example.json tenants.json
npm run tenant:key -- callblocker_android   # put the printed hash in tenants.json, give the key to the app
npm install
npm run dev                       # needs MongoDB at MONGODB_URI
# or the full stack:
docker compose up --build
npm test                          # 47 end-to-end tests against a real in-memory MongoDB
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
  secret, expire automatically (MongoDB TTL index), and allow at most 5 attempts (counted
  atomically). Responses don't reveal whether an email exists. Resends have a cooldown.
- **Input**: strict Zod schemas reject unknown fields (no mass assignment) and non-string values.
  Mongoose `sanitizeFilter` blocks NoSQL operator injection. JSON-only bodies are capped at 10 kB.
- **HTTP**: Helmet security headers, CORS allow-list, `Cache-Control: no-store` on API responses,
  `x-powered-by` removed, request IDs, and optional `X-API-Key` for service-to-service calls.
- **Operations**: configuration is validated at startup (weak or missing secrets refuse to boot;
  production requires Gmail), logs redact passwords, tokens and codes, there are health checks, and
  shutdown is graceful. The Docker image runs as a non-root user.
- **Tenant isolation**: the tenant is resolved from the hashed API key (never from client claims).
  There are no global models; every query uses the tenant's own collections. JWTs are bound to the
  tenant (`tid` + audience), reset codes are tenant-scoped, and browser origins are allow-listed per tenant.

## Structure

```
src/config/env.ts                  validated configuration
src/app.ts                         Express app (security middleware, routes, errors)
src/server.ts                      bootstrap + graceful shutdown
src/container.ts                   composition root (swap mailer etc.)
src/middleware/                    validation, auth, API key, rate limits, error handler
src/modules/auth/                  schemas, AuthService (use-cases), TokenService, PasswordService, models
src/modules/mail/                  Mailer port, GmailMailer (OAuth2), console/memory mailers, templates
src/modules/users/user.model.ts    User schema (bound per tenant)
src/tenancy/                       tenant config loader, registry (API key → tenant), per-tenant model factory
scripts/                           tenant:key (onboarding), tenant:migrate (legacy data → tenant)
docs/MULTI_TENANCY.md              multi-tenancy design & implementation plan
tests/                             supertest + mongodb-memory-server end-to-end tests
```
