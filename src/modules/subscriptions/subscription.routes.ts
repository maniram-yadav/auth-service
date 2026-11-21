import { Router, type Request, type RequestHandler } from 'express';
import { z } from 'zod';

import { safeEqual, sha256 } from '../../lib/crypto.js';
import { AppError } from '../../lib/errors.js';
import { requireAuth, validateBody } from '../../middleware/security.js';
import type { TenantContext } from '../../tenancy/tenant-registry.js';
import type { TokenService } from '../auth/token.service.js';
import type { PurchaseInput, SubscriptionService } from './subscription.service.js';
import { intervalSeconds, syncIntervalSchema, type SyncInterval } from './sync-interval.js';

const tenantOf = (req: Request): TenantContext => req.tenant!;

const purchaseSchema = z.strictObject({
  planId: z.enum(['six_months', 'one_year', 'lifetime'], { error: 'planId must be six_months, one_year or lifetime' }),
  provider: z.enum(['google_play', 'sandbox'], { error: 'provider must be google_play or sandbox' }),
  purchaseToken: z.string({ error: 'purchaseToken is required' }).min(10).max(4096),
});

/** Admin endpoints require X-Admin-Key (compared by SHA-256 hash). Disabled when no keys are configured. */
const requireAdmin =
  (keyHashes: readonly string[]): RequestHandler =>
  (req, _res, next) => {
    if (keyHashes.length === 0) throw AppError.notFound();
    const presented = req.get('x-admin-key');
    if (!presented || !keyHashes.some((h) => safeEqual(h, sha256(presented)))) {
      throw new AppError(401, 'UNAUTHORIZED', 'Invalid or missing admin key');
    }
    next();
  };

export function createSubscriptionRouter(subscriptions: SubscriptionService, tokens: TokenService): Router {
  const router = Router();
  const authenticated = requireAuth(tokens);

  /** Public catalog (tenant key only) so the app can show plans before purchase. */
  router.get('/plans', (_req, res) => {
    res.json({ plans: subscriptions.listPlans(), providers: subscriptions.providers() });
  });

  /** Current entitlement + the tenant's sync interval. The app calls this every sync interval. */
  router.get('/me', authenticated, async (req, res) => {
    res.json(await subscriptions.status(tenantOf(req), req.auth!.userId));
  });

  /** Redeem a verified store purchase. Idempotent per purchase token (also used to restore purchases). */
  router.post('/purchase', authenticated, validateBody(purchaseSchema), async (req, res) => {
    res.json(await subscriptions.purchase(tenantOf(req), req.auth!.userId, req.body as PurchaseInput));
  });

  return router;
}

export function createAdminRouter(subscriptions: SubscriptionService, adminKeyHashes: readonly string[]): Router {
  const router = Router();
  router.use(requireAdmin(adminKeyHashes));

  const view = (interval: SyncInterval) => ({ interval, intervalSeconds: intervalSeconds(interval) });

  router.get('/subscription-sync-interval', async (req, res) => {
    res.json(view(await subscriptions.getSyncInterval(tenantOf(req))));
  });

  router.put('/subscription-sync-interval', validateBody(syncIntervalSchema), async (req, res) => {
    res.json(view(await subscriptions.setSyncInterval(tenantOf(req), req.body as SyncInterval)));
  });

  return router;
}
