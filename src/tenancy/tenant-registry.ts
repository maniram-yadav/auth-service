import { sha256 } from '../lib/crypto.js';
import type { StorageProvider, TenantStore } from '../persistence/types.js';
import type { TenantConfig } from './tenant.js';

/** Everything a request needs to know about the tenant it belongs to. */
export interface TenantContext {
  id: string;
  config: TenantConfig;
  /** Repositories bound to this tenant's own collections / tables. */
  store: TenantStore;
}

/** In-memory index of the configured tenants, looked up by API key hash. */
export class TenantRegistry {
  private readonly byId = new Map<string, TenantConfig>();
  private readonly byKeyHash = new Map<string, TenantConfig>();

  constructor(
    tenants: readonly TenantConfig[],
    private readonly storage: StorageProvider,
  ) {
    for (const tenant of tenants) {
      this.byId.set(tenant.id, tenant);
      tenant.apiKeyHashes.forEach((hash) => this.byKeyHash.set(hash, tenant));
    }
  }

  /** Resolves a tenant from a presented API key (only its SHA-256 is compared). */
  findByApiKey(apiKey: string): TenantConfig | undefined {
    return this.byKeyHash.get(sha256(apiKey));
  }

  get(id: string): TenantConfig | undefined {
    return this.byId.get(id);
  }

  list(): TenantConfig[] {
    return [...this.byId.values()];
  }

  /** Union of browser origins of all enabled tenants (used for the CORS pre-flight). */
  allowedOrigins(): string[] {
    return [...new Set(this.list().filter((t) => t.enabled).flatMap((t) => t.allowedOrigins))];
  }

  async context(config: TenantConfig): Promise<TenantContext> {
    return { id: config.id, config, store: await this.storage.forTenant(config.id) };
  }
}
