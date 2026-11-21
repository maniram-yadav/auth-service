import { randomUUID } from 'node:crypto';

import type pg from 'pg';

import {
  DuplicatePurchaseError,
  type AppSettingsRepository,
  type NewPurchase,
  type PaymentProvider,
  type PlanId,
  type PurchaseRecord,
  type PurchaseRepository,
  type RuleSyncRepository,
  type SubscriptionRecord,
  type SubscriptionRepository,
  type SubscriptionUpsert,
  type SyncedRule,
} from '../types.js';

/** PostgreSQL DDL + repositories for subscriptions, purchases, synced rules and tenant settings. */

type Queryable = Pick<pg.Pool, 'query'>;

export interface AccountTables {
  users: string;
  subscriptions: string;
  purchases: string;
  userRules: string;
  appSettings: string;
  /** Unqualified names for constraint / index naming. */
  raw: { subscriptions: string; purchases: string; userRules: string; appSettings: string };
}

const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

export function accountDdl(t: AccountTables): string[] {
  const p = t.raw.purchases;
  return [
    `CREATE TABLE IF NOT EXISTS ${t.subscriptions} (
      user_id uuid PRIMARY KEY REFERENCES ${t.users}(id) ON DELETE CASCADE,
      plan_id varchar(20) NOT NULL CHECK (plan_id IN ('six_months', 'one_year', 'lifetime')),
      provider varchar(20) NOT NULL CHECK (provider IN ('google_play', 'sandbox')),
      product_id varchar(200) NOT NULL,
      purchase_token varchar(4096) NOT NULL,
      expires_at timestamptz,
      auto_renewing boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS ${t.purchases} (
      id uuid PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES ${t.users}(id) ON DELETE CASCADE,
      provider varchar(20) NOT NULL,
      purchase_token varchar(4096) NOT NULL,
      product_id varchar(200) NOT NULL,
      plan_id varchar(20) NOT NULL,
      order_id varchar(200),
      purchased_at timestamptz NOT NULL,
      expires_at timestamptz,
      created_at timestamptz NOT NULL,
      CONSTRAINT ${ident(`${p}_token_key`)} UNIQUE (provider, purchase_token)
    )`,
    `CREATE INDEX IF NOT EXISTS ${ident(`${p}_user_id_idx`)} ON ${t.purchases} (user_id)`,
    `CREATE TABLE IF NOT EXISTS ${t.userRules} (
      user_id uuid PRIMARY KEY REFERENCES ${t.users}(id) ON DELETE CASCADE,
      rules jsonb NOT NULL DEFAULT '[]'::jsonb,
      updated_at timestamptz NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS ${t.appSettings} (
      key varchar(100) PRIMARY KEY,
      value jsonb NOT NULL,
      updated_at timestamptz NOT NULL
    )`,
  ];
}

interface SubscriptionRow {
  user_id: string;
  plan_id: string;
  provider: string;
  product_id: string;
  purchase_token: string;
  expires_at: Date | null;
  auto_renewing: boolean;
  created_at: Date;
  updated_at: Date;
}

const toSubscription = (r: SubscriptionRow): SubscriptionRecord => ({
  userId: r.user_id,
  planId: r.plan_id as PlanId,
  provider: r.provider as PaymentProvider,
  productId: r.product_id,
  purchaseToken: r.purchase_token,
  expiresAt: r.expires_at,
  autoRenewing: r.auto_renewing,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

export class PgSubscriptionRepository implements SubscriptionRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: AccountTables,
  ) {}

  async get(userId: string) {
    const { rows } = await this.db.query<SubscriptionRow>(`SELECT * FROM ${this.t.subscriptions} WHERE user_id = $1`, [userId]);
    return rows[0] ? toSubscription(rows[0]) : null;
  }

  async upsert(s: SubscriptionUpsert) {
    const { rows } = await this.db.query<SubscriptionRow>(
      `INSERT INTO ${this.t.subscriptions}
         (user_id, plan_id, provider, product_id, purchase_token, expires_at, auto_renewing, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
       ON CONFLICT (user_id) DO UPDATE SET
         plan_id = EXCLUDED.plan_id, provider = EXCLUDED.provider, product_id = EXCLUDED.product_id,
         purchase_token = EXCLUDED.purchase_token, expires_at = EXCLUDED.expires_at,
         auto_renewing = EXCLUDED.auto_renewing, updated_at = now()
       RETURNING *`,
      [s.userId, s.planId, s.provider, s.productId, s.purchaseToken, s.expiresAt, s.autoRenewing],
    );
    return toSubscription(rows[0]!);
  }
}

interface PurchaseRow {
  id: string;
  user_id: string;
  provider: string;
  purchase_token: string;
  product_id: string;
  plan_id: string;
  order_id: string | null;
  purchased_at: Date;
  expires_at: Date | null;
  created_at: Date;
}

const toPurchase = (r: PurchaseRow): PurchaseRecord => ({
  id: r.id,
  userId: r.user_id,
  provider: r.provider as PaymentProvider,
  purchaseToken: r.purchase_token,
  productId: r.product_id,
  planId: r.plan_id as PlanId,
  orderId: r.order_id,
  purchasedAt: r.purchased_at,
  expiresAt: r.expires_at,
  createdAt: r.created_at,
});

export class PgPurchaseRepository implements PurchaseRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: AccountTables,
  ) {}

  async findByToken(provider: PaymentProvider, purchaseToken: string) {
    const { rows } = await this.db.query<PurchaseRow>(
      `SELECT * FROM ${this.t.purchases} WHERE provider = $1 AND purchase_token = $2`,
      [provider, purchaseToken],
    );
    return rows[0] ? toPurchase(rows[0]) : null;
  }

  async create(p: NewPurchase) {
    try {
      const { rows } = await this.db.query<PurchaseRow>(
        `INSERT INTO ${this.t.purchases}
           (id, user_id, provider, purchase_token, product_id, plan_id, order_id, purchased_at, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
         RETURNING *`,
        [randomUUID(), p.userId, p.provider, p.purchaseToken, p.productId, p.planId, p.orderId, p.purchasedAt, p.expiresAt],
      );
      return toPurchase(rows[0]!);
    } catch (e) {
      if ((e as { code?: string }).code === '23505') throw new DuplicatePurchaseError();
      throw e;
    }
  }
}

export class PgRuleSyncRepository implements RuleSyncRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: AccountTables,
  ) {}

  async list(userId: string) {
    const { rows } = await this.db.query<{ rules: SyncedRule[]; updated_at: Date }>(
      `SELECT rules, updated_at FROM ${this.t.userRules} WHERE user_id = $1`,
      [userId],
    );
    return { rules: rows[0]?.rules ?? [], updatedAt: rows[0]?.updated_at ?? null };
  }

  async replace(userId: string, rules: SyncedRule[]) {
    const { rows } = await this.db.query<{ updated_at: Date }>(
      `INSERT INTO ${this.t.userRules} (user_id, rules, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (user_id) DO UPDATE SET rules = EXCLUDED.rules, updated_at = now()
       RETURNING updated_at`,
      [userId, JSON.stringify(rules)],
    );
    return rows[0]!.updated_at;
  }
}

export class PgAppSettingsRepository implements AppSettingsRepository {
  constructor(
    private readonly db: Queryable,
    private readonly t: AccountTables,
  ) {}

  async get<T>(key: string) {
    const { rows } = await this.db.query<{ value: T }>(`SELECT value FROM ${this.t.appSettings} WHERE key = $1`, [key]);
    return rows[0]?.value ?? null;
  }

  async set(key: string, value: unknown) {
    await this.db.query(
      `INSERT INTO ${this.t.appSettings} (key, value, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [key, JSON.stringify(value)],
    );
  }
}
