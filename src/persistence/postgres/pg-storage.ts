import { randomUUID } from 'node:crypto';

import pg from 'pg';
import type { Logger } from 'pino';

import { physicalNames, TenantCache, type IsolationStrategy, type PhysicalNames } from '../naming.js';
import {
  DuplicateKeyError,
  type NewRefreshToken,
  type NewUser,
  type PasswordResetRepository,
  type RefreshTokenRepository,
  type ResetAttempt,
  type StorageProvider,
  type TenantStore,
  type UserRecord,
  type UserRepository,
} from '../types.js';
import {
  PgAppSettingsRepository,
  PgPurchaseRepository,
  PgRuleSyncRepository,
  PgSubscriptionRepository,
  accountDdl,
  type AccountTables,
} from './account-data.js';

type Queryable = Pick<pg.Pool, 'query'>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Quotes an identifier. Names are already restricted by the tenant-id pattern; this is defence in depth. */
const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

/** Fully-qualified, quoted table names of one tenant. */
interface Tables extends AccountTables {
  schema: string;
  users: string;
  refreshTokens: string;
  passwordResets: string;
  /** Unqualified names, used to build constraint / index names. */
  raw: PhysicalNames;
}

function tablesFor(names: PhysicalNames, sharedSchema: string): Tables {
  const schema = names.namespace ?? sharedSchema;
  const q = (t: string) => `${ident(schema)}.${ident(t)}`;
  return {
    schema,
    users: q(names.users),
    refreshTokens: q(names.refreshTokens),
    passwordResets: q(names.passwordResets),
    subscriptions: q(names.subscriptions),
    purchases: q(names.purchases),
    userRules: q(names.userRules),
    appSettings: q(names.appSettings),
    raw: names,
  };
}

/**
 * Idempotent DDL for one tenant. Constraint and index names embed the (tenant-prefixed) table
 * name because PostgreSQL index names must be unique within a schema.
 */
export function tenantDdl(t: Tables): string[] {
  const { users: u, refreshTokens: rt, passwordResets: pr } = t.raw;
  return [
    `CREATE SCHEMA IF NOT EXISTS ${ident(t.schema)}`,
    `CREATE TABLE IF NOT EXISTS ${t.users} (
      id uuid PRIMARY KEY,
      full_name varchar(100) NOT NULL,
      email varchar(254) NOT NULL,
      country char(2) NOT NULL,
      phone varchar(20) NOT NULL,
      password_hash text NOT NULL,
      password_changed_at timestamptz NOT NULL,
      token_version integer NOT NULL DEFAULT 0,
      failed_login_attempts integer NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
      lock_until timestamptz,
      last_login_at timestamptz,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL,
      CONSTRAINT ${ident(`${u}_email_key`)} UNIQUE (email),
      CONSTRAINT ${ident(`${u}_phone_key`)} UNIQUE (phone)
    )`,
    `CREATE TABLE IF NOT EXISTS ${t.refreshTokens} (
      id uuid PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES ${t.users}(id) ON DELETE CASCADE,
      token_hash char(64) NOT NULL,
      family uuid NOT NULL,
      expires_at timestamptz NOT NULL,
      revoked_at timestamptz,
      replaced_by_hash char(64),
      user_agent varchar(300),
      ip varchar(64),
      created_at timestamptz NOT NULL,
      CONSTRAINT ${ident(`${rt}_token_hash_key`)} UNIQUE (token_hash)
    )`,
    `CREATE INDEX IF NOT EXISTS ${ident(`${rt}_user_id_idx`)} ON ${t.refreshTokens} (user_id)`,
    `CREATE INDEX IF NOT EXISTS ${ident(`${rt}_family_idx`)} ON ${t.refreshTokens} (family)`,
    `CREATE INDEX IF NOT EXISTS ${ident(`${rt}_expires_at_idx`)} ON ${t.refreshTokens} (expires_at)`,
    `CREATE TABLE IF NOT EXISTS ${t.passwordResets} (
      id uuid PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES ${t.users}(id) ON DELETE CASCADE,
      code_hash char(64) NOT NULL,
      attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL,
      CONSTRAINT ${ident(`${pr}_user_id_key`)} UNIQUE (user_id)
    )`,
    `CREATE INDEX IF NOT EXISTS ${ident(`${pr}_expires_at_idx`)} ON ${t.passwordResets} (expires_at)`,
  ];
}

interface UserRow {
  id: string;
  full_name: string;
  email: string;
  country: string;
  phone: string;
  password_hash: string;
  password_changed_at: Date;
  token_version: number;
  failed_login_attempts: number;
  lock_until: Date | null;
  last_login_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

const toUser = (r: UserRow): UserRecord => ({
  id: r.id,
  fullName: r.full_name,
  email: r.email,
  country: r.country.trim(),
  phone: r.phone,
  passwordHash: r.password_hash,
  passwordChangedAt: r.password_changed_at,
  tokenVersion: r.token_version,
  failedLoginAttempts: r.failed_login_attempts,
  lockUntil: r.lock_until,
  lastLoginAt: r.last_login_at,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

class PgUserRepository implements UserRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: Tables,
  ) {}

  async findConflicts(email: string, phone: string) {
    const { rows } = await this.db.query<{ email: string; phone: string }>(
      `SELECT email, phone FROM ${this.t.users} WHERE email = $1 OR phone = $2`,
      [email, phone],
    );
    return { email: rows.some((r) => r.email === email), phone: rows.some((r) => r.phone === phone) };
  }

  async create(user: NewUser): Promise<UserRecord> {
    const now = new Date();
    try {
      const { rows } = await this.db.query<UserRow>(
        `INSERT INTO ${this.t.users}
           (id, full_name, email, country, phone, password_hash, password_changed_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7)
         RETURNING *`,
        [randomUUID(), user.fullName, user.email, user.country, user.phone, user.passwordHash, now],
      );
      return toUser(rows[0]!);
    } catch (e) {
      const err = e as { code?: string; constraint?: string };
      if (err.code === '23505') throw new DuplicateKeyError(err.constraint?.endsWith('_phone_key') ? 'phone' : 'email');
      throw e;
    }
  }

  private async findOne(column: 'id' | 'email' | 'phone', value: string) {
    const { rows } = await this.db.query<UserRow>(`SELECT * FROM ${this.t.users} WHERE ${column} = $1`, [value]);
    return rows[0] ? toUser(rows[0]) : null;
  }

  findById(id: string) {
    return UUID.test(id) ? this.findOne('id', id) : Promise.resolve(null);
  }

  findByEmail(email: string) {
    return this.findOne('email', email);
  }

  findByPhone(phone: string) {
    return this.findOne('phone', phone);
  }

  async getTokenVersion(id: string) {
    if (!UUID.test(id)) return null;
    const { rows } = await this.db.query<{ token_version: number }>(
      `SELECT token_version FROM ${this.t.users} WHERE id = $1`,
      [id],
    );
    return rows[0]?.token_version ?? null;
  }

  async recordFailedLogin(id: string, maxAttempts: number, lockUntil: Date) {
    // One statement: increment, and lock + reset the counter when the limit is reached.
    const { rows } = await this.db.query<{ locked: boolean }>(
      `UPDATE ${this.t.users} SET
         failed_login_attempts = CASE WHEN failed_login_attempts + 1 >= $2 THEN 0 ELSE failed_login_attempts + 1 END,
         lock_until = CASE WHEN failed_login_attempts + 1 >= $2 THEN $3::timestamptz ELSE lock_until END,
         updated_at = now()
       WHERE id = $1
       RETURNING (failed_login_attempts = 0 AND lock_until = $3::timestamptz) AS locked`,
      [id, maxAttempts, lockUntil],
    );
    return rows[0]?.locked ?? false;
  }

  async recordSuccessfulLogin(id: string, upgradedHash?: string) {
    await this.db.query(
      `UPDATE ${this.t.users} SET
         failed_login_attempts = 0, lock_until = NULL, last_login_at = now(), updated_at = now(),
         password_hash = COALESCE($2, password_hash)
       WHERE id = $1`,
      [id, upgradedHash ?? null],
    );
  }

  async setPassword(id: string, passwordHash: string) {
    const { rows } = await this.db.query<{ token_version: number }>(
      `UPDATE ${this.t.users} SET
         password_hash = $2, password_changed_at = now(), failed_login_attempts = 0, lock_until = NULL,
         token_version = token_version + 1, updated_at = now()
       WHERE id = $1
       RETURNING token_version`,
      [id, passwordHash],
    );
    return rows[0]?.token_version ?? 0;
  }

  async bumpTokenVersion(id: string) {
    if (!UUID.test(id)) return false;
    const res = await this.db.query(
      `UPDATE ${this.t.users} SET token_version = token_version + 1, updated_at = now() WHERE id = $1`,
      [id],
    );
    return (res.rowCount ?? 0) > 0;
  }
}

class PgRefreshTokenRepository implements RefreshTokenRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: Tables,
  ) {}

  async create(token: NewRefreshToken) {
    await this.db.query(
      `INSERT INTO ${this.t.refreshTokens} (id, user_id, token_hash, family, expires_at, user_agent, ip, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
      [randomUUID(), token.userId, token.tokenHash, token.family, token.expiresAt, token.userAgent, token.ip],
    );
  }

  async consumeActive(tokenHash: string, now: Date) {
    // Atomic: only one concurrent caller can flip revoked_at from NULL.
    const { rows } = await this.db.query<{ user_id: string; family: string }>(
      `UPDATE ${this.t.refreshTokens} SET revoked_at = $2
       WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2
       RETURNING user_id, family`,
      [tokenHash, now],
    );
    return rows[0] ? { userId: rows[0].user_id, family: rows[0].family } : null;
  }

  async findByHash(tokenHash: string) {
    const { rows } = await this.db.query<{ family: string; revoked_at: Date | null }>(
      `SELECT family, revoked_at FROM ${this.t.refreshTokens} WHERE token_hash = $1`,
      [tokenHash],
    );
    return rows[0] ? { family: rows[0].family, revokedAt: rows[0].revoked_at } : null;
  }

  async revokeFamily(family: string, now: Date) {
    await this.db.query(`UPDATE ${this.t.refreshTokens} SET revoked_at = $2 WHERE family = $1 AND revoked_at IS NULL`, [
      family,
      now,
    ]);
  }

  async revoke(tokenHash: string, now: Date) {
    await this.db.query(
      `UPDATE ${this.t.refreshTokens} SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`,
      [tokenHash, now],
    );
  }

  async revokeAllForUser(userId: string, now: Date) {
    await this.db.query(
      `UPDATE ${this.t.refreshTokens} SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId, now],
    );
  }

  async linkReplacement(oldHash: string, newHash: string) {
    await this.db.query(`UPDATE ${this.t.refreshTokens} SET replaced_by_hash = $2 WHERE token_hash = $1`, [oldHash, newHash]);
  }
}

class PgPasswordResetRepository implements PasswordResetRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: Tables,
  ) {}

  async findCreatedAt(userId: string) {
    const { rows } = await this.db.query<{ created_at: Date }>(
      `SELECT created_at FROM ${this.t.passwordResets} WHERE user_id = $1`,
      [userId],
    );
    return rows[0]?.created_at ?? null;
  }

  async replace(userId: string, codeHash: string, expiresAt: Date) {
    await this.db.query(
      `INSERT INTO ${this.t.passwordResets} (id, user_id, code_hash, attempts, expires_at, created_at)
       VALUES ($1, $2, $3, 0, $4, now())
       ON CONFLICT (user_id) DO UPDATE
         SET id = EXCLUDED.id, code_hash = EXCLUDED.code_hash, attempts = 0,
             expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at`,
      [randomUUID(), userId, codeHash, expiresAt],
    );
  }

  async consumeAttempt(userId: string, now: Date, maxAttempts: number): Promise<ResetAttempt | null> {
    const { rows } = await this.db.query<{ id: string; code_hash: string; attempts: number }>(
      `UPDATE ${this.t.passwordResets} SET attempts = attempts + 1
       WHERE user_id = $1 AND expires_at > $2 AND attempts < $3
       RETURNING id, code_hash, attempts`,
      [userId, now, maxAttempts],
    );
    const r = rows[0];
    return r ? { id: r.id, codeHash: r.code_hash, attempts: r.attempts } : null;
  }

  async delete(id: string) {
    await this.db.query(`DELETE FROM ${this.t.passwordResets} WHERE id = $1`, [id]);
  }

  async deleteForUser(userId: string) {
    await this.db.query(`DELETE FROM ${this.t.passwordResets} WHERE user_id = $1`, [userId]);
  }
}

export interface PgStorageOptions {
  connectionString: string;
  isolation: IsolationStrategy;
  /** Schema prefix for TENANT_ISOLATION=database (schema per tenant). */
  schemaPrefix: string;
  /** Schema holding the prefixed tables for TENANT_ISOLATION=collection. */
  sharedSchema: string;
  poolMax: number;
  ssl: boolean;
  purgeIntervalMinutes: number;
  logger: Logger;
}

/** PostgreSQL backend: prefixed tables per tenant, or a schema per tenant. */
export class PgStorageProvider implements StorageProvider {
  readonly driver = 'postgres' as const;
  readonly pool: pg.Pool;
  private readonly cache = new TenantCache<TenantStore>((id) => this.build(id));
  private ddlQueue: Promise<unknown> = Promise.resolve();
  private purgeTimer: NodeJS.Timeout | null = null;

  constructor(private readonly options: PgStorageOptions) {
    this.pool = new pg.Pool({
      connectionString: options.connectionString,
      max: options.poolMax,
      ssl: options.ssl ? { rejectUnauthorized: true } : undefined,
      connectionTimeoutMillis: 10_000,
      idleTimeoutMillis: 30_000,
    });
    // An idle client erroring (e.g. DB restart) must not crash the process.
    this.pool.on('error', (err) => options.logger.error({ err }, 'PostgreSQL pool error'));
  }

  async connect() {
    await this.pool.query('SELECT 1');
    this.options.logger.info('PostgreSQL connected');
    if (this.options.purgeIntervalMinutes > 0) {
      this.purgeTimer = setInterval(() => {
        this.purgeExpired().catch((err: unknown) => this.options.logger.error({ err }, 'purging expired rows failed'));
      }, this.options.purgeIntervalMinutes * 60_000);
      this.purgeTimer.unref();
    }
  }

  async disconnect() {
    if (this.purgeTimer) clearInterval(this.purgeTimer);
    await this.pool.end();
  }

  async isHealthy() {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  forTenant(tenantId: string) {
    return this.cache.get(tenantId);
  }

  async purgeExpired() {
    let removed = 0;
    for (const tenantId of this.cache.keys()) {
      const t = this.tables(tenantId);
      const a = await this.pool.query(`DELETE FROM ${t.refreshTokens} WHERE expires_at <= now()`);
      const b = await this.pool.query(`DELETE FROM ${t.passwordResets} WHERE expires_at <= now()`);
      removed += (a.rowCount ?? 0) + (b.rowCount ?? 0);
    }
    return removed;
  }

  private tables(tenantId: string): Tables {
    return tablesFor(physicalNames(this.options.isolation, tenantId, this.options.schemaPrefix), this.options.sharedSchema);
  }

  private async build(tenantId: string): Promise<TenantStore> {
    const t = this.tables(tenantId);
    await this.runDdl([...tenantDdl(t), ...accountDdl(t)]);
    return {
      users: new PgUserRepository(this.pool, t),
      refreshTokens: new PgRefreshTokenRepository(this.pool, t),
      passwordResets: new PgPasswordResetRepository(this.pool, t),
      subscriptions: new PgSubscriptionRepository(this.pool, t),
      purchases: new PgPurchaseRepository(this.pool, t),
      rules: new PgRuleSyncRepository(this.pool, t),
      settings: new PgAppSettingsRepository(this.pool, t),
    };
  }

  /**
   * Runs DDL in one transaction, serialised in-process and across instances (advisory lock),
   * so concurrent startups can't race on CREATE SCHEMA / CREATE TABLE.
   */
  private runDdl(statements: string[]): Promise<void> {
    const run = async () => {
      const client = await this.pool.connect();
      try {
        await client.query('BEGIN');
        await client.query("SELECT pg_advisory_xact_lock(hashtext('auth-service:ddl'))");
        for (const sql of statements) await client.query(sql);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw e;
      } finally {
        client.release();
      }
    };
    const next = this.ddlQueue.then(run, run);
    this.ddlQueue = next.catch(() => undefined);
    return next;
  }
}
