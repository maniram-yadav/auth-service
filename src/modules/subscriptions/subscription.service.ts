import type { Logger } from 'pino';

import { hmacSha256 } from '../../lib/crypto.js';
import { AppError } from '../../lib/errors.js';
import {
  DuplicatePurchaseError,
  type PaymentProvider,
  type PlanId,
  type SubscriptionRecord,
} from '../../persistence/types.js';
import type { TenantContext } from '../../tenancy/tenant-registry.js';
import { addMonths, type Plan } from './plans.js';
import { SYNC_INTERVAL_KEY, intervalSeconds, syncIntervalSchema, type SyncInterval } from './sync-interval.js';
import { PurchaseVerificationError, type PurchaseVerifier, type VerifiedPurchase } from './verifiers/verifier.js';

export interface SubscriptionStatus {
  subscription: {
    status: 'active' | 'expired' | 'none';
    planId: PlanId | null;
    /** ISO date; null when lifetime or no subscription. */
    expiresAt: string | null;
    lifetime: boolean;
    autoRenewing: boolean;
    provider: PaymentProvider | null;
  };
  /** How often the app must re-fetch this status. Stored per tenant in the database. */
  sync: { interval: SyncInterval; intervalSeconds: number };
  /** Pass to the store as obfuscatedAccountId so purchases are bound to this account. */
  accountToken: string;
  serverTime: string;
}

export interface PurchaseInput {
  planId: PlanId;
  provider: PaymentProvider;
  purchaseToken: string;
}

export interface SubscriptionServiceDeps {
  plans: Plan[];
  verifiers: PurchaseVerifier[];
  defaultSyncInterval: SyncInterval;
  /** Secret used to derive the per-account store binding token. */
  accountSecret: string;
  logger: Logger;
}

const VERIFICATION_ERRORS: Record<PurchaseVerificationError['reason'], { status: number; code: 'PURCHASE_INVALID' | 'PAYMENT_PENDING' | 'PAYMENT_PROVIDER_UNAVAILABLE' }> = {
  invalid: { status: 400, code: 'PURCHASE_INVALID' },
  expired: { status: 400, code: 'PURCHASE_INVALID' },
  account_mismatch: { status: 403, code: 'PURCHASE_INVALID' },
  pending: { status: 409, code: 'PAYMENT_PENDING' },
  unavailable: { status: 503, code: 'PAYMENT_PROVIDER_UNAVAILABLE' },
};

/** Plans, purchases, entitlement status and the tenant's sync interval. */
export class SubscriptionService {
  private readonly verifiers: Map<PaymentProvider, PurchaseVerifier>;

  constructor(private readonly deps: SubscriptionServiceDeps) {
    this.verifiers = new Map(deps.verifiers.map((v) => [v.provider, v]));
  }

  listPlans() {
    return this.deps.plans.map(({ id, title, priceUsd, durationMonths, productId, storeType }) => ({
      id,
      title,
      priceUsd,
      durationMonths,
      lifetime: durationMonths === null,
      productId,
      storeType,
    }));
  }

  providers(): PaymentProvider[] {
    return [...this.verifiers.keys()];
  }

  accountToken(tenant: TenantContext, userId: string): string {
    // Domain-separated HMAC; 64 hex chars (Play's obfuscatedAccountId limit is 64).
    return hmacSha256(`store-account:${tenant.id}:${userId}`, this.deps.accountSecret);
  }

  // ---------------------------------------------------------------- sync interval

  async getSyncInterval(tenant: TenantContext): Promise<SyncInterval> {
    const stored = await tenant.store.settings.get<unknown>(SYNC_INTERVAL_KEY);
    const parsed = syncIntervalSchema.safeParse(stored);
    return parsed.success ? parsed.data : this.deps.defaultSyncInterval;
  }

  async setSyncInterval(tenant: TenantContext, interval: SyncInterval): Promise<SyncInterval> {
    await tenant.store.settings.set(SYNC_INTERVAL_KEY, interval);
    this.deps.logger.info({ tenant: tenant.id, interval }, 'subscription sync interval updated');
    return interval;
  }

  // ---------------------------------------------------------------- status

  async status(tenant: TenantContext, userId: string): Promise<SubscriptionStatus> {
    let sub = await tenant.store.subscriptions.get(userId);
    if (sub) sub = await this.refreshRenewal(tenant, sub);
    return this.buildStatus(tenant, userId, sub);
  }

  private async buildStatus(tenant: TenantContext, userId: string, sub: SubscriptionRecord | null): Promise<SubscriptionStatus> {
    const interval = await this.getSyncInterval(tenant);
    const now = Date.now();
    const lifetime = !!sub && sub.expiresAt === null;
    const active = !!sub && (lifetime || sub.expiresAt!.getTime() > now);
    return {
      subscription: {
        status: !sub ? 'none' : active ? 'active' : 'expired',
        planId: sub?.planId ?? null,
        expiresAt: sub?.expiresAt?.toISOString() ?? null,
        lifetime,
        autoRenewing: sub?.autoRenewing ?? false,
        provider: sub?.provider ?? null,
      },
      sync: { interval, intervalSeconds: intervalSeconds(interval) },
      accountToken: this.accountToken(tenant, userId),
      serverTime: new Date(now).toISOString(),
    };
  }

  /** Auto-renewing store subscriptions: once the stored expiry passed, ask the store for the renewed expiry. */
  private async refreshRenewal(tenant: TenantContext, sub: SubscriptionRecord): Promise<SubscriptionRecord> {
    if (sub.expiresAt === null || sub.expiresAt.getTime() > Date.now() || !sub.autoRenewing) return sub;
    const verifier = this.verifiers.get(sub.provider);
    const plan = this.deps.plans.find((p) => p.id === sub.planId);
    if (!verifier || !plan || sub.provider === 'sandbox') return sub;
    try {
      const verified = await verifier.verify({
        plan,
        purchaseToken: sub.purchaseToken,
        expectedAccountId: this.accountToken(tenant, sub.userId),
      });
      return tenant.store.subscriptions.upsert({ ...sub, expiresAt: verified.expiresAt, autoRenewing: verified.autoRenewing });
    } catch (e) {
      if (e instanceof PurchaseVerificationError && e.reason === 'expired') {
        return tenant.store.subscriptions.upsert({ ...sub, autoRenewing: false });
      }
      this.deps.logger.warn({ err: e, tenant: tenant.id }, 'renewal check failed; keeping stored expiry');
      return sub;
    }
  }

  // ---------------------------------------------------------------- purchase

  async purchase(tenant: TenantContext, userId: string, input: PurchaseInput): Promise<SubscriptionStatus> {
    const plan = this.deps.plans.find((p) => p.id === input.planId);
    if (!plan) throw AppError.badRequest('Unknown plan', [{ field: 'planId', message: 'Unknown plan' }]);
    const verifier = this.verifiers.get(input.provider);
    if (!verifier) {
      throw AppError.badRequest('Payment provider not available', [{ field: 'provider', message: 'Payment provider not available' }]);
    }

    // Idempotent: re-sending a token already redeemed by this user just returns the status (restore).
    const existing = await tenant.store.purchases.findByToken(input.provider, input.purchaseToken);
    if (existing) return this.alreadyRedeemed(tenant, userId, existing.userId);

    let verified: VerifiedPurchase;
    try {
      verified = await verifier.verify({ plan, purchaseToken: input.purchaseToken, expectedAccountId: this.accountToken(tenant, userId) });
    } catch (e) {
      if (e instanceof PurchaseVerificationError) {
        const mapped = VERIFICATION_ERRORS[e.reason];
        throw new AppError(mapped.status, mapped.code, e.message);
      }
      throw e;
    }

    const current = await tenant.store.subscriptions.get(userId);
    const expiresAt = this.computeExpiry(plan, input.provider, verified, current);

    try {
      await tenant.store.purchases.create({
        userId,
        provider: input.provider,
        purchaseToken: input.purchaseToken,
        productId: plan.productId,
        planId: plan.id,
        orderId: verified.orderId,
        purchasedAt: verified.purchasedAt,
        expiresAt,
      });
    } catch (e) {
      if (e instanceof DuplicatePurchaseError) {
        const owner = await tenant.store.purchases.findByToken(input.provider, input.purchaseToken);
        return this.alreadyRedeemed(tenant, userId, owner?.userId ?? '');
      }
      throw e;
    }

    // Never downgrade an active lifetime entitlement.
    const keepLifetime = current?.expiresAt === null;
    const sub = keepLifetime
      ? current!
      : await tenant.store.subscriptions.upsert({
          userId,
          planId: plan.id,
          provider: input.provider,
          productId: plan.productId,
          purchaseToken: input.purchaseToken,
          expiresAt,
          autoRenewing: verified.autoRenewing,
        });

    this.deps.logger.info(
      { tenant: tenant.id, userId, planId: plan.id, provider: input.provider, expiresAt: expiresAt?.toISOString() ?? 'never' },
      'subscription purchased',
    );
    return this.buildStatus(tenant, userId, sub);
  }

  private async alreadyRedeemed(tenant: TenantContext, userId: string, ownerId: string): Promise<SubscriptionStatus> {
    if (ownerId !== userId) {
      throw new AppError(409, 'PURCHASE_ALREADY_USED', 'This purchase is already linked to another account');
    }
    return this.status(tenant, userId);
  }

  private computeExpiry(plan: Plan, provider: PaymentProvider, verified: VerifiedPurchase, current: SubscriptionRecord | null): Date | null {
    if (plan.durationMonths === null) return null;
    if (provider !== 'sandbox' && verified.expiresAt) return verified.expiresAt;
    // Sandbox / prepaid: extend from the later of now or the remaining time.
    const remaining = current?.expiresAt && current.expiresAt.getTime() > Date.now() ? current.expiresAt : new Date();
    return addMonths(remaining, plan.durationMonths);
  }
}
