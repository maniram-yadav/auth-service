import { PurchaseVerificationError, type PurchaseVerifier, type VerifiedPurchase, type VerifyRequest } from './verifier.js';

export const SANDBOX_TOKEN_PATTERN = /^sandbox_[A-Za-z0-9_-]{16,128}$/;

/**
 * Development/test provider: accepts tokens of the form `sandbox_<random>` without charging.
 * Only registered when PAYMENTS_SANDBOX_ENABLED=true, which env validation forbids in production.
 */
export class SandboxVerifier implements PurchaseVerifier {
  readonly provider = 'sandbox' as const;

  async verify({ purchaseToken }: VerifyRequest): Promise<VerifiedPurchase> {
    if (!SANDBOX_TOKEN_PATTERN.test(purchaseToken)) {
      throw new PurchaseVerificationError('Invalid sandbox purchase token', 'invalid');
    }
    // Expiry for timed plans is computed by the service (stacks on top of any remaining time).
    return { orderId: `SANDBOX.${purchaseToken.slice(8, 24)}`, purchasedAt: new Date(), expiresAt: null, autoRenewing: false };
  }
}
