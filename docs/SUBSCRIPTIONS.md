# Subscriptions, Free Trial & Sync: Design and Setup

Covers **auth-service** (server) and the **Call Blocker Android app** (client).

| Plan | Price | Google Play product type | Access |
|------|-------|--------------------------|--------|
| 6 months | **$10** | Auto-renewing subscription (`callblocker_6_months`, 6-month base plan) | until expiry, renews |
| 1 year | **$15** | Auto-renewing subscription (`callblocker_1_year`, yearly base plan) | until expiry, renews |
| Lifetime | **$20** | One-time, non-consumable in-app product (`callblocker_lifetime`) | forever |

---

## 1. User journey

```
Install ──► 30-day free trial (no account) ──► trial ends ──► Sign-up screen (forced)
                 │                                                    │
                 └─ optional early sign-up from Settings / banner     ▼
                                                     Sign-up: local rules uploaded to account
                                                                       │
                                                                       ▼
                                                        Plans screen: 6 months | 1 year | Lifetime
                                                                       │ Google Play purchase
                                                                       ▼
                                   auth-service verifies with Google ──► entitlement stored (DB)
                                                                       │
                                                                       ▼
                                 phone caches expiry + sync interval ──► native screening checks
                                                                          it on EVERY incoming call
```

| State (`Access`) | Condition | What the app shows | Calls blocked? |
|------------------|-----------|--------------------|----------------|
| `trial` | < 30 days since first launch | Full app + "X days left" banner | ✅ |
| `subscribed` | Lifetime, or `now < expiresAt` | Full app | ✅ |
| `needs_signup` | Trial over, signed out | Sign-up / login only | ❌ |
| `needs_subscription` | Trial over, signed in, no active plan | Plans screen only | ❌ |

The same rule is implemented twice: `src/core/entitlement/access.ts` (UI, Jest-tested) and
`EntitlementFilter` in the native call screening chain (Kotlin, JUnit-tested). The native check is
the one that matters: it runs on each incoming call, even when the app is closed.

---

## 2. Architecture

```
Android app                                                     auth-service
───────────                                                     ────────────
PaywallScreen ─► PurchaseService ─► BillingProvider             /api/v1/subscriptions
                    │               ├─ PlayBillingProvider        GET  /plans
                    │               │   (expo-iap, Play Billing)  GET  /me        (auth)
                    │               └─ SandboxBillingProvider     POST /purchase  (auth)
                    ▼                                             │
             SubscriptionSyncService ─────── HTTPS ─────────────► SubscriptionService
                    │  snapshot {expiresAt, lifetime,               ├─ PurchaseVerifier (strategy)
                    │   serverTime, syncIntervalSeconds}            │   ├─ GooglePlayVerifier
                    ▼                                               │   └─ SandboxVerifier
          EntitlementStore (native SharedPreferences)               ├─ <t>_subscriptions
                    ▲                                               ├─ <t>_purchases
   CallScreeningService → EntitlementFilter (every call)            └─ <t>_app_settings (sync interval)
                                                                 /api/v1/sync/rules
RuleSyncService ─── merge after sign-in / replace after edits ──► <t>_user_rules
                                                                 /api/v1/admin/subscription-sync-interval
```

All new tables and collections exist for both database drivers (MongoDB and PostgreSQL) and per tenant (see
[MULTI_TENANCY.md](MULTI_TENANCY.md) and [DATABASE_DRIVERS.md](DATABASE_DRIVERS.md)).

---

## 3. Server API

All endpoints need the tenant `X-API-Key`. "(auth)" endpoints also need `Authorization: Bearer <accessToken>`.

### `GET /api/v1/subscriptions/plans`
```json
{ "plans": [
    { "id": "six_months", "title": "6 months", "priceUsd": 10, "durationMonths": 6, "lifetime": false,
      "productId": "callblocker_6_months", "storeType": "subs" },
    { "id": "one_year", "title": "1 year", "priceUsd": 15, "durationMonths": 12, "lifetime": false,
      "productId": "callblocker_1_year", "storeType": "subs" },
    { "id": "lifetime", "title": "Lifetime", "priceUsd": 20, "durationMonths": null, "lifetime": true,
      "productId": "callblocker_lifetime", "storeType": "in-app" } ],
  "providers": ["google_play"] }
```

### `GET /api/v1/subscriptions/me` (auth)
The app calls this once per **sync interval**. The response carries the expiry **and** the current interval:
```json
{ "subscription": { "status": "active", "planId": "one_year", "expiresAt": "2027-11-21T08:00:00.000Z",
                    "lifetime": false, "autoRenewing": true, "provider": "google_play" },
  "sync": { "interval": { "value": 1, "unit": "hour" }, "intervalSeconds": 3600 },
  "accountToken": "<64 hex>",
  "serverTime": "2026-11-21T08:00:00.000Z" }
```
- `status` is `active`, `expired` or `none`. `expiresAt` is `null` for lifetime.
- For auto-renewing Google subscriptions, once the stored expiry has passed, the server asks Google for the
  renewed expiry before answering.
- `accountToken` is an HMAC of tenant and user. The app passes it to Google Play as `obfuscatedAccountId`, and the server
  rejects purchases bound to another account.
- `serverTime` feeds the phone's clock guard.

### `POST /api/v1/subscriptions/purchase` (auth)
```json
{ "planId": "one_year", "provider": "google_play", "purchaseToken": "<token from Google Play>" }
```
Returns the same body as `/me`. Server steps:
1. Validate the plan and provider (`sandbox` only if `PAYMENTS_SANDBOX_ENABLED=true`).
2. **Idempotency / anti-sharing:** a token already redeemed by this user returns the current status (this is
   also how "Restore purchases" works). A token redeemed by another account returns **409 `PURCHASE_ALREADY_USED`**.
3. **Verify with Google** (Play Developer API, service-account OAuth2):
   - subscriptions: `purchases.subscriptionsv2.get` → product must match, state `ACTIVE`, `IN_GRACE_PERIOD`
     or `CANCELED` (still paid up), expiry in the future, account binding matches.
   - lifetime: `purchases.products.get` → `purchaseState = 0`, account binding matches.
   - **Acknowledge** the purchase server-side (Play refunds unacknowledged purchases after 3 days).
4. Record the purchase (unique `(provider, purchaseToken)`) and upsert the user's entitlement:
   - lifetime → `expiresAt = null`.
   - Google subscription → Google's `expiryTime`.
   - sandbox → stacks on any remaining time (e.g. 6 months + 1 year = 18 months).
   - an active **lifetime is never downgraded** by a later purchase.

| Error | When |
|-------|------|
| `400 PURCHASE_INVALID` | Unknown/invalid token, wrong product, cancelled/refunded, expired |
| `403 PURCHASE_INVALID` | Purchase bound to a different account |
| `409 PAYMENT_PENDING` | Google Play payment still pending (e.g. cash payment) |
| `409 PURCHASE_ALREADY_USED` | Token already redeemed by another account |
| `503 PAYMENT_PROVIDER_UNAVAILABLE` | Google API unreachable (retry later) |

### Rule sync: `GET|POST /api/v1/sync/rules` (auth)
```json
{ "mode": "merge", "rules": [ { "type": "PREFIX", "countryIso": "US", "anyCountry": false,
                                "pattern": "800", "label": "Telemarketers", "enabled": true } ] }
```
- **`merge`**, used right after sign-up or login: a union of the account's rules and the phone's rules (the phone wins
  on conflicts). Rules created during the trial are saved to the account. Rules from the account
  (reinstall, new phone) are imported into the phone.
- **`replace`**, used 2 s after any local edit (debounced): the phone's list becomes the account's list, so deletions
  sync too.
- Rule identity is type + country (or `*`) + digits, so `800` and `8 0 0` are the same rule. Max 2,000 rules.
  This route accepts up to 512 kB; all other routes keep the 10 kB limit.

### Admin: sync interval, stored in the database
`GET|PUT /api/v1/admin/subscription-sync-interval`, with header `X-Admin-Key` (plus the tenant `X-API-Key`):
```bash
curl -X PUT https://auth.example.com/api/v1/admin/subscription-sync-interval \
  -H "X-API-Key: <tenant key>" -H "X-Admin-Key: <admin key>" -H "Content-Type: application/json" \
  -d '{"value": 15, "unit": "minute"}'
# → {"interval":{"value":15,"unit":"minute"},"intervalSeconds":900}
```
- Units: `minute`, `hour`, `day`, `month` (30 days), `year` (365 days). Value is a whole number from 1 to 1000. The maximum is 1 year.
- Stored **per tenant** in `<tenant>_app_settings` (key `subscription.syncInterval`). Until set, the default comes from
  `SUBSCRIPTION_SYNC_INTERVAL_VALUE` / `_UNIT` (1 hour).
- Phones pick up the new interval **at their next sync**, because every `/me` response carries it.
- Admin API is disabled (404) unless `ADMIN_API_KEY_HASHES` is set. Generate a key with `npm run admin:key`.

---

## 4. Phone-side storage and sync

**Native `EntitlementRepository`** (SharedPreferences `call_blocker_entitlement`) stores:
- `installedAt`: set on first launch. The trial ends at `installedAt + 30 days`.
- `planId`, `expiresAt`, `lifetime`: the last server answer.
- `syncIntervalSeconds`, `lastSyncAt`: when the next sync is due.
- `maxObservedTime`: **clock guard**. The highest time ever seen (device clock at each call, plus `serverTime` at each
  sync). "Now" is never earlier than this, so setting the phone's clock back doesn't revive a trial or an expired plan.

**When the app syncs** (`SubscriptionSyncService.syncIfDue` → `GET /subscriptions/me`):

| Trigger | Notes |
|---------|-------|
| App launch and every return to the foreground | Only if `now − lastSyncAt ≥ syncIntervalSeconds` |
| Timer while the app is open | Fires exactly when the next sync is due; re-armed after each sync |
| Background task (`expo-background-task`) | Android WorkManager, at most every 15 min (OS minimum); uses the stored refresh token |
| Sign-in, purchase, restore, "Sync now" | Always |

When offline, the cached expiry keeps working. Blocking stops only once the cached `expiresAt` passes.
**Sign-out** clears the cached subscription on the phone, because the plan belongs to the account. Signing in again restores it.

**Token storage:** the refresh token and profile live in `expo-secure-store` (Android Keystore). The access token is kept in memory
only and refreshed transparently.

---

## 5. Setup

### 5.1 Google Play Console (production billing)
1. Upload a release build (internal testing track is fine) with package `com.callblocker.app`.
2. **Monetize → Subscriptions**: create `callblocker_6_months` with a **6-month** base plan at $10, and
   `callblocker_1_year` with a **yearly** base plan at $15. Activate both base plans.
3. **Monetize → In-app products**: create `callblocker_lifetime` (one-time) at $20.
4. **Google Cloud**: create a service account, then enable the *Google Play Android Developer API*. In
   **Play Console → Users and permissions**, invite the service-account email with *View financial data* and
   *Manage orders and subscriptions*. Download its JSON key.
5. auth-service `.env`:
   ```env
   GOOGLE_PLAY_PACKAGE_NAME=com.callblocker.app
   GOOGLE_PLAY_SERVICE_ACCOUNT_FILE=/run/secrets/play-service-account.json
   PAYMENTS_SANDBOX_ENABLED=false
   ```
6. Add license testers (Play Console → Setup → License testing) to buy with test cards before going live.

### 5.2 App build configuration (`call-blocker/.env`)
```env
EXPO_PUBLIC_AUTH_API_URL=https://auth.example.com
EXPO_PUBLIC_AUTH_API_KEY=<tenant key from: npm run tenant:key -- callblocker_android>
EXPO_PUBLIC_BILLING_MODE=play          # "sandbox" for local development
EXPO_PUBLIC_ANDROID_PACKAGE=com.callblocker.app
```
Rebuild the dev client after adding the billing, background-task and secure-store native modules:
`npx expo run:android` or `eas build --profile development`.

### 5.3 Local development without Play Console
- auth-service: `PAYMENTS_SANDBOX_ENABLED=true` (refused when `NODE_ENV=production`).
- app: `EXPO_PUBLIC_BILLING_MODE=sandbox`. "Subscribe" then redeems a `sandbox_…` token immediately, with no charge.
- To test the end of the trial quickly, clear app data and change `TRIAL_MILLIS` (Kotlin) temporarily, or test
  the logic through the unit tests.

---

## 6. Security notes

- **The server is the source of truth.** Entitlements are granted only after store verification. The client never asserts
  a plan.
- **Purchase tokens** can't be replayed across accounts (unique per provider and token, plus the account-binding check).
- **Clock tampering** is mitigated by the monotonic clock guard (§4).
- **Trial abuse:** the trial is per installation (local, no account needed). Reinstalling or clearing data restarts it. Making
  it device-bound would need Play Integrity / device attestation. That is listed as a future enhancement.
- **Sandbox payments** can't be enabled in production (startup validation).
- **Admin keys** are stored only as SHA-256 hashes and compared in constant time.

---

## 7. Tests

| Where | What |
|-------|------|
| `auth-service/tests/subscriptions.test.ts` (×2 drivers) | Plans/prices, default interval, sandbox stacking, lifetime no-downgrade, idempotent restore, cross-account replay (409), validation; Google Play verifier against a fake Play API (real RS256 JWT, state/product/account checks, acknowledgement, pending, renewal refresh); admin interval (auth, validation, per tenant, disabled) |
| `auth-service/tests/rules-sync.test.ts` (×2 drivers) | Merge and replace semantics, formatting-insensitive identity, limits, isolation per user and tenant |
| `call-blocker/src/core/entitlement/__tests__` | Trial/signup/subscription states, sync due calculation, interval descriptions |
| `call-blocker/src/account/__tests__` | Sign-up uploads trial rules and imports account rules, expiry and interval stored locally, interval change picked up, token refresh, sandbox purchase activates blocking, cancel, sign-out, screening stops when not entitled |
| `call-blocker/.../EntitlementTest.kt` | 30-day trial, timed and lifetime plans, clock guard, filter allows calls when not entitled |
