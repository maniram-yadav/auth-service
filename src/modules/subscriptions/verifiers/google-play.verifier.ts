import jwt from 'jsonwebtoken';
import type { Logger } from 'pino';

import { PurchaseVerificationError, type PurchaseVerifier, type VerifiedPurchase, type VerifyRequest } from './verifier.js';

export interface GoogleServiceAccount {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

export interface GooglePlayConfig {
  packageName: string;
  serviceAccount: GoogleServiceAccount;
  logger: Logger;
  /** Injectable for tests. */
  fetch?: typeof fetch;
}

const SCOPE = 'https://www.googleapis.com/auth/androidpublisher';
const API = 'https://androidpublisher.googleapis.com/androidpublisher/v3/applications';

/** Subscription states that still grant access until expiryTime. */
const ENTITLED_STATES = new Set([
  'SUBSCRIPTION_STATE_ACTIVE',
  'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
  'SUBSCRIPTION_STATE_CANCELED', // cancelled = won't renew, still valid until expiry
]);

interface SubscriptionV2 {
  subscriptionState?: string;
  acknowledgementState?: string;
  latestOrderId?: string;
  startTime?: string;
  lineItems?: { productId?: string; expiryTime?: string; autoRenewingPlan?: { autoRenewEnabled?: boolean } }[];
  externalAccountIdentifiers?: { obfuscatedExternalAccountId?: string };
}

interface ProductPurchase {
  purchaseState?: number; // 0 purchased, 1 canceled, 2 pending
  acknowledgementState?: number; // 0 pending, 1 acknowledged
  orderId?: string;
  purchaseTimeMillis?: string;
  obfuscatedExternalAccountId?: string;
}

/**
 * Verifies Google Play purchases with the Play Developer API (service-account OAuth2), checks the
 * product, state and account binding, and acknowledges the purchase server-side (Play refunds
 * unacknowledged purchases after 3 days).
 */
export class GooglePlayVerifier implements PurchaseVerifier {
  readonly provider = 'google_play' as const;
  private readonly http: typeof fetch;
  private accessToken: { value: string; expiresAt: number } | null = null;

  constructor(private readonly config: GooglePlayConfig) {
    this.http = config.fetch ?? fetch;
  }

  async verify(request: VerifyRequest): Promise<VerifiedPurchase> {
    return request.plan.storeType === 'subs' ? this.verifySubscription(request) : this.verifyProduct(request);
  }

  private async verifySubscription({ plan, purchaseToken, expectedAccountId }: VerifyRequest): Promise<VerifiedPurchase> {
    const base = `${API}/${encodeURIComponent(this.config.packageName)}/purchases`;
    const sub = await this.get<SubscriptionV2>(`${base}/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}`);

    const item = sub.lineItems?.find((li) => li.productId === plan.productId);
    if (!item?.expiryTime) throw new PurchaseVerificationError('Purchase is not for this plan', 'invalid');
    if (sub.subscriptionState === 'SUBSCRIPTION_STATE_PENDING') {
      throw new PurchaseVerificationError('Payment is still pending', 'pending');
    }
    this.checkAccount(sub.externalAccountIdentifiers?.obfuscatedExternalAccountId, expectedAccountId);

    const expiresAt = new Date(item.expiryTime);
    if (!ENTITLED_STATES.has(sub.subscriptionState ?? '') || expiresAt.getTime() <= Date.now()) {
      throw new PurchaseVerificationError('Subscription is not active', 'expired');
    }

    if (sub.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_PENDING') {
      await this.post(`${base}/subscriptions/${encodeURIComponent(plan.productId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`);
    }
    return {
      orderId: sub.latestOrderId ?? null,
      purchasedAt: sub.startTime ? new Date(sub.startTime) : new Date(),
      expiresAt,
      autoRenewing: item.autoRenewingPlan?.autoRenewEnabled ?? false,
    };
  }

  private async verifyProduct({ plan, purchaseToken, expectedAccountId }: VerifyRequest): Promise<VerifiedPurchase> {
    const url = `${API}/${encodeURIComponent(this.config.packageName)}/purchases/products/${encodeURIComponent(plan.productId)}/tokens/${encodeURIComponent(purchaseToken)}`;
    const p = await this.get<ProductPurchase>(url);
    if (p.purchaseState === 2) throw new PurchaseVerificationError('Payment is still pending', 'pending');
    if (p.purchaseState !== 0) throw new PurchaseVerificationError('Purchase was cancelled or refunded', 'invalid');
    this.checkAccount(p.obfuscatedExternalAccountId, expectedAccountId);
    if (p.acknowledgementState === 0) await this.post(`${url}:acknowledge`);
    return {
      orderId: p.orderId ?? null,
      purchasedAt: p.purchaseTimeMillis ? new Date(Number(p.purchaseTimeMillis)) : new Date(),
      expiresAt: null,
      autoRenewing: false,
    };
  }

  /** A purchase made for another account can't be redeemed (token sharing protection). */
  private checkAccount(actual: string | undefined, expected: string) {
    if (actual && actual !== expected) {
      throw new PurchaseVerificationError('Purchase belongs to a different account', 'account_mismatch');
    }
  }

  private async get<T>(url: string): Promise<T> {
    const res = await this.http(url, { headers: { Authorization: `Bearer ${await this.token()}` } });
    if (res.status === 404 || res.status === 400 || res.status === 410) {
      throw new PurchaseVerificationError('Purchase token not recognised by Google Play', 'invalid');
    }
    if (!res.ok) {
      this.config.logger.error({ status: res.status }, 'Google Play API error');
      throw new PurchaseVerificationError('Google Play is unavailable, try again', 'unavailable');
    }
    return (await res.json()) as T;
  }

  private async post(url: string): Promise<void> {
    const res = await this.http(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${await this.token()}`, 'Content-Type': 'application/json' },
      body: '{}',
    });
    // Already-acknowledged returns 400 on some products; acknowledgement is best-effort and idempotent.
    if (!res.ok && res.status !== 400) this.config.logger.warn({ status: res.status }, 'Google Play acknowledge failed');
  }

  /** OAuth2 JWT-bearer flow for the service account; token cached until shortly before expiry. */
  private async token(): Promise<string> {
    if (this.accessToken && this.accessToken.expiresAt > Date.now() + 60_000) return this.accessToken.value;
    const { client_email, private_key, token_uri = 'https://oauth2.googleapis.com/token' } = this.config.serviceAccount;
    const now = Math.floor(Date.now() / 1000);
    const assertion = jwt.sign({ iss: client_email, scope: SCOPE, aud: token_uri, iat: now, exp: now + 3600 }, private_key, {
      algorithm: 'RS256',
    });
    const res = await this.http(token_uri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString(),
    });
    if (!res.ok) {
      this.config.logger.error({ status: res.status }, 'Google OAuth token request failed');
      throw new PurchaseVerificationError('Google Play is unavailable, try again', 'unavailable');
    }
    const body = (await res.json()) as { access_token: string; expires_in: number };
    this.accessToken = { value: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 };
    return body.access_token;
  }
}
