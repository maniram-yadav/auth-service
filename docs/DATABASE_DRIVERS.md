# Database Drivers: MongoDB or PostgreSQL

`auth-service` stores its data in **MongoDB** or **PostgreSQL**. The backend is chosen with one
environment flag, `DB_DRIVER`. Both drivers support the same features, security guarantees and
tenant isolation strategies, and the same 78-test suite runs against each.

---

## 1. Quick setup

### MongoDB
```env
DB_DRIVER=mongodb
MONGODB_URI=mongodb://localhost:27017/auth_service
```

### PostgreSQL
```env
DB_DRIVER=postgres
DATABASE_URL=postgres://auth_service:secret@localhost:5432/auth_service
PG_SCHEMA=public                # schema for tenant-prefixed tables
PG_POOL_MAX=10
PG_SSL=false                    # true for managed DBs (verifies the server certificate)
PG_PURGE_INTERVAL_MINUTES=60    # cleanup of expired tokens/codes
```

Create the Postgres database and user once. The service creates its tables itself:
```sql
CREATE ROLE auth_service LOGIN PASSWORD 'secret';
CREATE DATABASE auth_service OWNER auth_service;
-- With TENANT_ISOLATION=database the role also creates one schema per tenant:
GRANT CREATE ON DATABASE auth_service TO auth_service;
```

### Docker Compose
```bash
cp .env.example .env && cp tenants.example.json tenants.json   # set DB_DRIVER in .env
docker compose --profile mongodb  up --build    # DB_DRIVER=mongodb
docker compose --profile postgres up --build    # DB_DRIVER=postgres
```

On startup the log shows `MongoDB connected` or `PostgreSQL connected`, then
`tenants ready { driver, isolation, tenants }`. `GET /health/ready` reports the active driver:
`{"status":"ok","database":"up","driver":"postgres"}`.

---

## 2. Configuration reference

| Variable | Driver | Default | Description |
|----------|--------|---------|-------------|
| `DB_DRIVER` | both | `mongodb` | `mongodb` or `postgres` |
| `MONGODB_URI` | mongodb | — | Required when `DB_DRIVER=mongodb` |
| `DATABASE_URL` | postgres | — | Required when `DB_DRIVER=postgres`. Standard libpq URL; `?sslmode=` is honoured |
| `PG_SCHEMA` | postgres | `public` | Schema holding the tenant-prefixed tables (`collection` strategy) |
| `PG_POOL_MAX` | postgres | `10` | Max pooled connections per instance |
| `PG_SSL` | postgres | `false` | `true` = TLS with certificate verification |
| `PG_PURGE_INTERVAL_MINUTES` | postgres | `60` | Interval for deleting expired refresh tokens and reset codes (`0` disables) |
| `TENANT_ISOLATION` | both | `collection` | See §3 |
| `TENANT_DB_PREFIX` | both | `auth_` | Database (Mongo) or schema (Postgres) prefix for the `database` strategy |

Startup fails fast with a clear message if the URL for the selected driver is missing.

---

## 3. Tenant isolation per driver

| `TENANT_ISOLATION` | MongoDB | PostgreSQL |
|--------------------|---------|------------|
| `collection` (default) | One database; collections `<tenant>_users`, `<tenant>_refresh_tokens`, `<tenant>_password_resets` | One schema (`PG_SCHEMA`); tables `<tenant>_users`, `<tenant>_refresh_tokens`, `<tenant>_password_resets` |
| `database` | One **database** per tenant: `<prefix><tenant>.users`, … | One **schema** per tenant: `<prefix><tenant>.users`, … |

Each tenant's collections or tables (and their indexes and constraints) are created at startup for
every configured tenant. A tenant first seen at runtime gets them on its first request.

---

## 4. PostgreSQL schema (per tenant)

Created idempotently with `CREATE … IF NOT EXISTS`, in one transaction guarded by a PostgreSQL advisory lock,
so several instances can start at once safely.

```sql
CREATE TABLE "<schema>"."<t>_users" (
  id uuid PRIMARY KEY,
  full_name varchar(100) NOT NULL,
  email varchar(254) NOT NULL,           -- stored lower-case
  country char(2) NOT NULL,
  phone varchar(20) NOT NULL,            -- E.164
  password_hash text NOT NULL,           -- Argon2id
  password_changed_at timestamptz NOT NULL,
  token_version integer NOT NULL DEFAULT 0,
  failed_login_attempts integer NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
  lock_until timestamptz,
  last_login_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT "<t>_users_email_key" UNIQUE (email),
  CONSTRAINT "<t>_users_phone_key" UNIQUE (phone)
);

CREATE TABLE "<schema>"."<t>_refresh_tokens" (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES "<t>_users"(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,   -- SHA-256 of the opaque token
  family uuid NOT NULL,                  -- rotation family (reuse detection)
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  replaced_by_hash char(64),
  user_agent varchar(300), ip varchar(64),
  created_at timestamptz NOT NULL
);  -- + indexes on user_id, family, expires_at

CREATE TABLE "<schema>"."<t>_password_resets" (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE REFERENCES "<t>_users"(id) ON DELETE CASCADE,
  code_hash char(64) NOT NULL,           -- HMAC-SHA256("<tenant>:<code>")
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL
);  -- + index on expires_at
```

Subscription feature tables (same per-tenant naming; see [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)):

```sql
CREATE TABLE "<t>_subscriptions" (user_id uuid PRIMARY KEY REFERENCES "<t>_users"(id) ON DELETE CASCADE,
  plan_id varchar(20) CHECK (plan_id IN ('six_months','one_year','lifetime')), provider varchar(20),
  product_id varchar(200), purchase_token varchar(4096), expires_at timestamptz /* NULL = lifetime */,
  auto_renewing boolean, created_at timestamptz, updated_at timestamptz);
CREATE TABLE "<t>_purchases" (id uuid PRIMARY KEY, user_id uuid REFERENCES "<t>_users"(id) ON DELETE CASCADE,
  provider varchar(20), purchase_token varchar(4096), product_id varchar(200), plan_id varchar(20),
  order_id varchar(200), purchased_at timestamptz, expires_at timestamptz, created_at timestamptz,
  UNIQUE (provider, purchase_token));                      -- replay / sharing protection
CREATE TABLE "<t>_user_rules" (user_id uuid PRIMARY KEY REFERENCES "<t>_users"(id) ON DELETE CASCADE,
  rules jsonb NOT NULL, updated_at timestamptz);           -- whole rule set, replaced atomically
CREATE TABLE "<t>_app_settings" (key varchar(100) PRIMARY KEY, value jsonb, updated_at timestamptz);
  -- e.g. key 'subscription.syncInterval' → {"value":1,"unit":"hour"}
```
MongoDB uses the same names as collections, with a unique index on `userId` (subscriptions, user_rules),
`(provider, purchaseToken)` (purchases) and `key` (app_settings).

Constraint and index names include the tenant-prefixed table name, because PostgreSQL index names must be
unique within a schema.

---

## 5. Behavioural parity

| Concern | MongoDB | PostgreSQL |
|---------|---------|------------|
| User id | ObjectId (hex string) | UUID v4 (generated in Node) |
| Unique email/phone per tenant | Unique indexes → `11000` | Unique constraints → `23505` (field taken from the constraint name) |
| Refresh-token rotation (exactly one winner) | `findOneAndUpdate` on `revokedAt: null` | `UPDATE … WHERE revoked_at IS NULL … RETURNING` |
| Reset-code attempt limit (race-free) | `findOneAndUpdate` with `$inc` + `attempts < max` | `UPDATE … SET attempts = attempts + 1 WHERE attempts < $max RETURNING` |
| Failed-login count + lock | Atomic `$inc`, then lock | One `UPDATE` with `CASE` (increment, lock and reset in one statement) |
| One active reset code per user | Delete + insert (unique index on `userId`) | `INSERT … ON CONFLICT (user_id) DO UPDATE` |
| Expired tokens and codes | TTL indexes (automatic) | Ignored by every query (`expires_at > now`); deleted every `PG_PURGE_INTERVAL_MINUTES` |
| Injection protection | `sanitizeFilter` + strict schemas | Parameterised queries only; identifiers come from validated tenant ids and are quoted |
| Health | Connection state | `SELECT 1` |

The contract tests in `tests/storage.test.ts` check each row of this table on both drivers, including
concurrency cases (5 parallel refreshes: exactly 1 succeeds; 8 parallel reset guesses: exactly 5 counted).

---

## 6. Architecture

```
AuthService / TokenService / requireAuth          (no database imports)
        │  tenant.store.users | refreshTokens | passwordResets
        ▼
src/persistence/types.ts        ports: UserRepository, RefreshTokenRepository,
                                       PasswordResetRepository, StorageProvider
        ├── mongo/mongo-storage.ts     Mongoose models bound per tenant
        └── postgres/pg-storage.ts     node-postgres Pool + per-tenant DDL + SQL repositories
src/persistence/index.ts        createStorage(env): picks the provider from DB_DRIVER
src/persistence/naming.ts       physical collection/table names for both strategies
```

**Adding another database** (e.g. MySQL): implement `StorageProvider` and the three repository interfaces,
add a case to `createStorage`, add the driver to `DRIVERS` in `tests/drivers.ts`, and the full suite runs against it.

---

## 7. Switching drivers or moving data

The drivers don't share data. Changing `DB_DRIVER` on a running system points the service at a
different, empty store. To move existing accounts, copy them per tenant:

| MongoDB `<t>_users` field | PostgreSQL `<t>_users` column |
|---------------------------|-------------------------------|
| `_id` (ObjectId) | `id`: generate a new UUID and keep a mapping for `refresh_tokens.user_id` |
| `fullName`, `email`, `country`, `phone` | `full_name`, `email`, `country`, `phone` |
| `passwordHash` | `password_hash` (Argon2id hashes are portable, so users keep their passwords) |
| `tokenVersion`, `failedLoginAttempts`, `lockUntil`, `lastLoginAt`, `passwordChangedAt`, `createdAt`, `updatedAt` | snake_case equivalents |

Refresh tokens and reset codes are short-lived. It is simplest not to migrate them: users sign in again once.
Plan this before go-live where possible.

`npm run tenant:migrate` (single-tenant → tenant collections) is MongoDB-only, because the pre-tenancy version
only supported MongoDB.

---

## 8. Production checklist

**PostgreSQL**
- Use a dedicated role that owns the database (or has `CREATE` on it, for schema-per-tenant).
- Set `PG_SSL=true` (or `?sslmode=verify-full`) for anything outside a private network.
- Size `PG_POOL_MAX × instances` below the server's `max_connections`, or put PgBouncer in front.
  The service runs no session-level state outside the startup DDL transaction.
- Back up with `pg_dump`. Per-tenant restore is easiest with `TENANT_ISOLATION=database` (schema per tenant).

**MongoDB**
- Use a replica set in production (needed for durability and failover).
- Use a user scoped to the auth database (`readWrite`, plus `dbAdmin` for index creation).
- Back up with `mongodump`. Per-tenant restore is easiest with `TENANT_ISOLATION=database`.

**Both**
- Choose the driver and isolation strategy before go-live. Changing either later needs a data move (§7).
- Keep the database private. Only `auth-service` should reach it.

---

## 9. Testing

```bash
npm test
```

Global test setup starts **both** a real MongoDB (`mongodb-memory-server`) and a real PostgreSQL (PGlite served over
the Postgres wire protocol, so the production `pg` driver is used). Every suite (auth, security, tenancy and the storage
contract, subscriptions, rule sync) runs once per driver: **156 tests, 78 per driver**.
