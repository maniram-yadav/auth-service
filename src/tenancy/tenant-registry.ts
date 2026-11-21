import { sha256 } from '../lib/crypto.js';
import type { TenantConfig } from './tenant.js';
import type { TenantModelFactory, TenantModels } from './tenant-models.js';

/** Everything a request needs to know about the tenant it belongs to. */
export interface TenantContext {
  id: string;
  config: TenantConfig;
  models: TenantModels;
}

/** In-memory index of the configured tenants, looked up by API key hash. */
export class TenantRegistry {
  private readonly byId = new Map<string, TenantConfig>();
  private readonly byKeyHash = new Map<string, TenantConfig>();

  constructor(
    tenants: readonly TenantConfig[],
    private readonly models: TenantModelFactory,
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
    return { id: config.id, config, models: await this.models.get(config.id) };
  }
}
