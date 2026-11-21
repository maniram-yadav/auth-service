import mongoose, { type Connection, type Model } from 'mongoose';

import { passwordResetSchema, type PasswordReset } from '../modules/auth/models/password-reset.model.js';
import { refreshTokenSchema, type RefreshToken } from '../modules/auth/models/refresh-token.model.js';
import { userSchema, type User } from '../modules/users/user.model.js';
import { TENANT_ID_PATTERN } from './tenant.js';

/** The Mongoose models of one tenant. Every query in the service goes through these. */
export interface TenantModels {
  users: Model<User>;
  refreshTokens: Model<RefreshToken>;
  passwordResets: Model<PasswordReset>;
}

export type IsolationStrategy = 'collection' | 'database';

/** Logical collection suffixes; the physical name depends on the isolation strategy. */
const COLLECTIONS = {
  users: 'users',
  refreshTokens: 'refresh_tokens',
  passwordResets: 'password_resets',
} as const;

/** Physical names for a tenant, e.g. collection strategy → "web_shop_users". */
export function physicalNames(strategy: IsolationStrategy, tenantId: string, dbPrefix: string) {
  return strategy === 'collection'
    ? {
        database: null,
        users: `${tenantId}_${COLLECTIONS.users}`,
        refreshTokens: `${tenantId}_${COLLECTIONS.refreshTokens}`,
        passwordResets: `${tenantId}_${COLLECTIONS.passwordResets}`,
      }
    : {
        database: `${dbPrefix}${tenantId}`,
        ...COLLECTIONS,
      };
}

/**
 * Creates (once) and caches each tenant's models.
 * - "collection": one database, collections prefixed with the tenant id (default).
 * - "database":   one database per tenant (`<prefix><tenantId>`), un-prefixed collections.
 * Index creation (unique email/phone, TTLs) runs once per tenant and is awaited before first use.
 */
export class TenantModelFactory {
  private readonly cache = new Map<string, Promise<TenantModels>>();

  constructor(
    private readonly strategy: IsolationStrategy,
    private readonly dbPrefix: string,
    private readonly connection: Connection = mongoose.connection,
  ) {}

  get(tenantId: string): Promise<TenantModels> {
    if (!TENANT_ID_PATTERN.test(tenantId)) throw new Error(`Invalid tenant id: ${tenantId}`);
    let entry = this.cache.get(tenantId);
    if (!entry) {
      entry = this.build(tenantId);
      // Don't cache failures (e.g. DB briefly unavailable) — retry on the next request.
      entry.catch(() => this.cache.delete(tenantId));
      this.cache.set(tenantId, entry);
    }
    return entry;
  }

  private async build(tenantId: string): Promise<TenantModels> {
    const names = physicalNames(this.strategy, tenantId, this.dbPrefix);
    const conn = names.database ? this.connection.useDb(names.database, { useCache: true }) : this.connection;
    // Model names must be unique per connection; prefix them in the shared-connection strategy.
    const modelName = (base: string) => (names.database ? base : `${tenantId}:${base}`);

    const models: TenantModels = {
      users: conn.models[modelName('User')] ?? conn.model<User>(modelName('User'), userSchema, names.users),
      refreshTokens:
        conn.models[modelName('RefreshToken')] ??
        conn.model<RefreshToken>(modelName('RefreshToken'), refreshTokenSchema, names.refreshTokens),
      passwordResets:
        conn.models[modelName('PasswordReset')] ??
        conn.model<PasswordReset>(modelName('PasswordReset'), passwordResetSchema, names.passwordResets),
    };
    await Promise.all([models.users.init(), models.refreshTokens.init(), models.passwordResets.init()]);
    return models;
  }
}
