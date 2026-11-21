import type { PaymentProvider } from '../../../persistence/types.js';
import type { Plan } from '../plans.js';

export interface VerifyRequest {
  plan: Plan;
  purchaseToken: string;
  /** Opaque per-user value the app passed to the store (obfuscatedAccountId); checked when present. */
  expectedAccountId: string;
}

/** What a store confirmed about a purchase. */
export interface VerifiedPurchase {
  orderId: string | null;
  purchasedAt: Date;
  /** null for lifetime. For sandbox timed plans the service computes the expiry. */
  expiresAt: Date | null;
  autoRenewing: boolean;
}

export class PurchaseVerificationError extends Error {
  constructor(
    message: string,
    readonly reason: 'invalid' | 'pending' | 'expired' | 'account_mismatch' | 'unavailable',
  ) {
    super(message);
    this.name = 'PurchaseVerificationError';
  }
}

/** Strategy per payment provider (Google Play, sandbox; add Stripe/App Store by implementing this). */
export interface PurchaseVerifier {
  readonly provider: PaymentProvider;
  /** @throws PurchaseVerificationError */
  verify(request: VerifyRequest): Promise<VerifiedPurchase>;
}
