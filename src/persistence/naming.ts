import { TENANT_ID_PATTERN } from '../tenancy/tenant.js';

/**
 * Tenant isolation strategy (same setting for both drivers):
 * - "collection": shared database (MongoDB) / shared schema (PostgreSQL); names prefixed with the tenant id.
 * - "database":   database per tenant (MongoDB) / schema per tenant (PostgreSQL); un-prefixed names.
 */
export type IsolationStrategy = 'collection' | 'database';

const BASE = {
  users: 'users',
  refreshTokens: 'refresh_tokens',
  passwordResets: 'password_resets',
  subscriptions: 'subscriptions',
  purchases: 'purchases',
  userRules: 'user_rules',
  appSettings: 'app_settings',
} as const;

export type LogicalName = keyof typeof BASE;

export type PhysicalNames = {
  /** MongoDB database / PostgreSQL schema, or null for the shared one. */
  namespace: string | null;
} & Record<LogicalName, string>;

/** Physical collection / table names for a tenant, e.g. "web_portal_users". */
export function physicalNames(strategy: IsolationStrategy, tenantId: string, prefix: string): PhysicalNames {
  if (!TENANT_ID_PATTERN.test(tenantId)) throw new Error(`Invalid tenant id: ${tenantId}`);
  if (strategy === 'database') return { namespace: `${prefix}${tenantId}`, ...BASE };
  const prefixed = Object.fromEntries(
    Object.entries(BASE).map(([key, name]) => [key, `${tenantId}_${name}`]),
  ) as Record<LogicalName, string>;
  return { namespace: null, ...prefixed };
}

/** Caches one promise per tenant; failed initialisations are evicted so the next call retries. */
export class TenantCache<T> {
  private readonly entries = new Map<string, Promise<T>>();

  constructor(private readonly build: (tenantId: string) => Promise<T>) {}

  get(tenantId: string): Promise<T> {
    let entry = this.entries.get(tenantId);
    if (!entry) {
      entry = this.build(tenantId);
      entry.catch(() => this.entries.delete(tenantId));
      this.entries.set(tenantId, entry);
    }
    return entry;
  }

  keys(): string[] {
    return [...this.entries.keys()];
  }

  values(): Promise<T>[] {
    return [...this.entries.values()];
  }
}
