import { createHash, generateKeyPairSync } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createLogger } from '../src/lib/logger.js';
import { GooglePlayVerifier } from '../src/modules/subscriptions/verifiers/google-play.verifier.js';
import { SandboxVerifier } from '../src/modules/subscriptions/verifiers/sandbox.verifier.js';
import { DRIVERS, testDriver } from './drivers.js';
import { buildApp, validUser } from './helpers.js';

const ADMIN_KEY = 'test-admin-key-0123456789';
const ADMIN_HASH = createHash('sha256').update(ADMIN_KEY).digest('hex');
const DAY = 86_400_000;

/** Minimal fake of the Google OAuth + Play Developer API. */
function fakeGooglePlay() {
  const state = {
    subscription: {} as Record<string, unknown>,
    product: {} as Record<string, unknown>,
    acknowledged: [] as string[],
    tokenRequests: 0,
  };
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    if (url.startsWith('https://oauth2.googleapis.com/token')) {
      state.tokenRequests += 1;
      expect(String(init?.body)).toContain('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer');
      return json({ access_token: 'fake-access-token', expires_in: 3600 });
    }
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer fake-access-token');
    if (url.endsWith(':acknowledge')) {
      state.acknowledged.push(url);
      return json({});
    }
    if (url.includes('/subscriptionsv2/tokens/')) return url.includes('unknown') ? json({}, 404) : json(state.subscription);
    if (url.includes('/purchases/products/')) return json(state.product);
    return json({ error: 'not found' }, 404);
  }) as typeof fetch;

  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const verifier = new GooglePlayVerifier({
    packageName: 'com.callblocker.app',
    serviceAccount: { client_email: 'svc@test.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
    logger: createLogger({ NODE_ENV: 'test', LOG_LEVEL: 'silent' }),
    fetch: fetchImpl,
  });
  return { state, verifier };
}

describe.each(DRIVERS)('subscriptions on %s', (driver) => {
  const db = testDriver(driver, 'subs');
  const google = fakeGooglePlay();
  const { api, web, container } = buildApp(
    db,
    { ADMIN_API_KEY_HASHES: ADMIN_HASH },
    { verifiers: [google.verifier, new SandboxVerifier()] },
  );

  beforeAll(() => db.start());
  afterAll(() => db.stop());
  beforeEach(async () => {
    await db.clear();
    google.state.acknowledged.length = 0;
  });

  async function signUp(client = api, overrides: Record<string, string> = {}) {
    const res = await client.post('/api/v1/auth/register').send({ ...validUser, ...overrides }).expect(201);
    return { auth: `Bearer ${res.body.tokens.accessToken}`, userId: res.body.user.id as string };
  }
  const sandboxToken = (n: number | string) => `sandbox_${String(n).padStart(20, 'x')}`;
  const buy = (auth: string, planId: string, purchaseToken: string, provider = 'sandbox') =>
    api.post('/api/v1/subscriptions/purchase').set('Authorization', auth).send({ planId, provider, purchaseToken });

  describe('plans and status', () => {
    it('lists the three plans with their prices', async () => {
      const res = await api.get('/api/v1/subscriptions/plans').expect(200);
      expect(res.body.plans).toEqual([
        expect.objectContaining({ id: 'six_months', priceUsd: 10, durationMonths: 6, storeType: 'subs' }),
        expect.objectContaining({ id: 'one_year', priceUsd: 15, durationMonths: 12, storeType: 'subs' }),
        expect.objectContaining({ id: 'lifetime', priceUsd: 20, durationMonths: null, lifetime: true, storeType: 'in-app' }),
      ]);
      expect(res.body.providers).toEqual(expect.arrayContaining(['google_play', 'sandbox']));
    });

    it('reports no subscription plus the default sync interval', async () => {
      const { auth } = await signUp();
      const res = await api.get('/api/v1/subscriptions/me').set('Authorization', auth).expect(200);
      expect(res.body.subscription).toMatchObject({ status: 'none', planId: null, expiresAt: null, lifetime: false });
      expect(res.body.sync).toEqual({ interval: { value: 1, unit: 'hour' }, intervalSeconds: 3600 });
      expect(res.body.accountToken).toMatch(/^[a-f0-9]{64}$/);
      expect(Date.parse(res.body.serverTime)).toBeGreaterThan(0);
    });

    it('requires authentication', async () => {
      await api.get('/api/v1/subscriptions/me').expect(401);
      await api.post('/api/v1/subscriptions/purchase').send({ planId: 'lifetime', provider: 'sandbox', purchaseToken: sandboxToken(1) }).expect(401);
    });
  });

  describe('sandbox purchases', () => {
    it('grants 6 months, then stacks 1 year on top', async () => {
      const { auth } = await signUp();
      const six = await buy(auth, 'six_months', sandboxToken(1)).expect(200);
      expect(six.body.subscription).toMatchObject({ status: 'active', planId: 'six_months', lifetime: false, provider: 'sandbox' });
      const sixExpiry = Date.parse(six.body.subscription.expiresAt);
      expect(sixExpiry - Date.now()).toBeGreaterThan(180 * DAY);
      expect(sixExpiry - Date.now()).toBeLessThan(185 * DAY);

      const year = await buy(auth, 'one_year', sandboxToken(2)).expect(200);
      const yearExpiry = Date.parse(year.body.subscription.expiresAt);
      expect(yearExpiry - sixExpiry).toBeGreaterThan(364 * DAY);
      expect(yearExpiry - sixExpiry).toBeLessThan(367 * DAY);
    });

    it('lifetime never expires and is not downgraded by later purchases', async () => {
      const { auth } = await signUp();
      const life = await buy(auth, 'lifetime', sandboxToken(3)).expect(200);
      expect(life.body.subscription).toMatchObject({ status: 'active', planId: 'lifetime', lifetime: true, expiresAt: null });
      const after = await buy(auth, 'six_months', sandboxToken(4)).expect(200);
      expect(after.body.subscription).toMatchObject({ planId: 'lifetime', lifetime: true, expiresAt: null });
    });

    it('is idempotent per token and blocks reuse by another account', async () => {
      const first = await signUp();
      const token = sandboxToken(5);
      const a = await buy(first.auth, 'one_year', token).expect(200);
      const again = await buy(first.auth, 'one_year', token).expect(200); // restore
      expect(again.body.subscription.expiresAt).toBe(a.body.subscription.expiresAt);

      const second = await signUp(api, { email: 'other@example.com', phone: '+12125550188' });
      const stolen = await buy(second.auth, 'one_year', token).expect(409);
      expect(stolen.body.error.code).toBe('PURCHASE_ALREADY_USED');
    });

    it('rejects malformed tokens, unknown plans and disabled providers', async () => {
      const { auth } = await signUp();
      expect((await buy(auth, 'lifetime', 'sandbox_short')).body.error.code).toBe('PURCHASE_INVALID');
      await buy(auth, 'forever', sandboxToken(6)).expect(400);
      await buy(auth, 'lifetime', sandboxToken(7), 'paypal').expect(400);
    });

    it('keeps entitlements per tenant', async () => {
      const mobile = await signUp(api);
      await buy(mobile.auth, 'lifetime', sandboxToken(8)).expect(200);
      const website = await signUp(web);
      const res = await web.get('/api/v1/subscriptions/me').set('Authorization', website.auth).expect(200);
      expect(res.body.subscription.status).toBe('none');
    });
  });

  describe('Google Play purchases', () => {
    const activeSub = (accountId: string, expiry: Date, ack = 'ACKNOWLEDGEMENT_STATE_PENDING') => ({
      subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE',
      acknowledgementState: ack,
      latestOrderId: 'GPA.1234-5678',
      startTime: new Date().toISOString(),
      lineItems: [{ productId: 'callblocker_1_year', expiryTime: expiry.toISOString(), autoRenewingPlan: { autoRenewEnabled: true } }],
      externalAccountIdentifiers: { obfuscatedExternalAccountId: accountId },
    });

    async function accountToken(auth: string) {
      return (await api.get('/api/v1/subscriptions/me').set('Authorization', auth)).body.accountToken as string;
    }

    it('verifies a subscription with Google, uses its expiry and acknowledges it', async () => {
      const { auth } = await signUp();
      const expiry = new Date(Date.now() + 365 * DAY);
      google.state.subscription = activeSub(await accountToken(auth), expiry);
      const res = await buy(auth, 'one_year', 'play-token-0001', 'google_play').expect(200);
      expect(res.body.subscription).toMatchObject({ status: 'active', planId: 'one_year', provider: 'google_play', autoRenewing: true });
      expect(res.body.subscription.expiresAt).toBe(expiry.toISOString());
      expect(google.state.acknowledged).toHaveLength(1);
      expect(google.state.acknowledged[0]).toContain('/purchases/subscriptions/callblocker_1_year/tokens/play-token-0001:acknowledge');
    });

    it('rejects pending payments, foreign accounts, wrong products and unknown tokens', async () => {
      const { auth } = await signUp();
      const mine = await accountToken(auth);
      const future = new Date(Date.now() + 30 * DAY);

      google.state.subscription = { ...activeSub(mine, future), subscriptionState: 'SUBSCRIPTION_STATE_PENDING' };
      expect((await buy(auth, 'one_year', 'play-token-0002', 'google_play').expect(409)).body.error.code).toBe('PAYMENT_PENDING');

      google.state.subscription = activeSub('someone-else', future);
      expect((await buy(auth, 'one_year', 'play-token-0003', 'google_play').expect(403)).body.error.code).toBe('PURCHASE_INVALID');

      google.state.subscription = activeSub(mine, future);
      await buy(auth, 'six_months', 'play-token-0004', 'google_play').expect(400); // token is for the 1-year product

      await buy(auth, 'one_year', 'play-token-unknown', 'google_play').expect(400);
    });

    it('verifies the lifetime one-time product', async () => {
      const { auth } = await signUp();
      google.state.product = {
        purchaseState: 0,
        acknowledgementState: 0,
        orderId: 'GPA.9999',
        purchaseTimeMillis: String(Date.now()),
        obfuscatedExternalAccountId: await accountToken(auth),
      };
      const res = await buy(auth, 'lifetime', 'play-token-life-01', 'google_play').expect(200);
      expect(res.body.subscription).toMatchObject({ lifetime: true, expiresAt: null, provider: 'google_play' });
      expect(google.state.acknowledged[0]).toContain('/purchases/products/callblocker_lifetime/tokens/play-token-life-01:acknowledge');
    });

    it('picks up renewals from Google once the stored expiry has passed', async () => {
      const { auth, userId } = await signUp();
      const mine = await accountToken(auth);
      google.state.subscription = activeSub(mine, new Date(Date.now() + 10 * DAY));
      await buy(auth, 'one_year', 'play-token-0005', 'google_play').expect(200);

      // Simulate the stored period ending; Google now reports the renewed expiry.
      const tenant = await container.tenants.context(container.tenants.get('mobile_app')!);
      const stored = (await tenant.store.subscriptions.get(userId))!;
      await tenant.store.subscriptions.upsert({ ...stored, expiresAt: new Date(Date.now() - 1000) });
      const renewed = new Date(Date.now() + 375 * DAY);
      google.state.subscription = activeSub(mine, renewed, 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED');

      const res = await api.get('/api/v1/subscriptions/me').set('Authorization', auth).expect(200);
      expect(res.body.subscription).toMatchObject({ status: 'active', expiresAt: renewed.toISOString() });
    });
  });

  describe('admin: subscription sync interval (stored in the database)', () => {
    const PATH = '/api/v1/admin/subscription-sync-interval';
    const putInterval = (body: object, client = api) => client.put(PATH).set('X-Admin-Key', ADMIN_KEY).send(body);

    it('requires the admin key', async () => {
      await api.get(PATH).expect(401);
      await api.get(PATH).set('X-Admin-Key', 'wrong-key').expect(401);
      await api.get(PATH).set('X-Admin-Key', ADMIN_KEY).expect(200);
    });

    it('updates the interval and returns it with every status sync', async () => {
      const { auth } = await signUp();
      const res = await putInterval({ value: 15, unit: 'minute' }).expect(200);
      expect(res.body).toEqual({ interval: { value: 15, unit: 'minute' }, intervalSeconds: 900 });

      const status = await api.get('/api/v1/subscriptions/me').set('Authorization', auth).expect(200);
      expect(status.body.sync).toEqual({ interval: { value: 15, unit: 'minute' }, intervalSeconds: 900 });

      await putInterval({ value: 2, unit: 'month' }).expect(200);
      const later = await api.get('/api/v1/subscriptions/me').set('Authorization', auth).expect(200);
      expect(later.body.sync.intervalSeconds).toBe(2 * 30 * 86_400);

      await putInterval({ value: 1, unit: 'year' }).expect(200);
      expect((await api.get(PATH).set('X-Admin-Key', ADMIN_KEY)).body.intervalSeconds).toBe(365 * 86_400);
    });

    it('validates the interval', async () => {
      await putInterval({ value: 1, unit: 'week' }).expect(400);
      await putInterval({ value: 0, unit: 'hour' }).expect(400);
      await putInterval({ value: 2, unit: 'year' }).expect(400);
      await putInterval({ value: 1.5, unit: 'hour' }).expect(400);
    });

    it('is per tenant', async () => {
      await putInterval({ value: 5, unit: 'minute' }).expect(200);
      const webRes = await web.get(PATH).set('X-Admin-Key', ADMIN_KEY).expect(200);
      expect(webRes.body.interval).toEqual({ value: 1, unit: 'hour' });
    });

    it('is disabled when no admin keys are configured', async () => {
      const noAdmin = buildApp(db);
      await noAdmin.api.get(PATH).set('X-Admin-Key', ADMIN_KEY).expect(404);
    });
  });
});
