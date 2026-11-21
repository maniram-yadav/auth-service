import mongoose from 'mongoose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { loadTenantConfigs } from '../src/tenancy/tenant.js';
import { physicalNames } from '../src/tenancy/tenant-models.js';
import { buildApp, clearDb, connectTestDb, disconnectTestDb, resetCodeFrom, validUser } from './helpers.js';
import { TEST_KEYS, WEB_ORIGIN } from './setup-env.js';

const { api, web, client, raw, mailer } = buildApp();

beforeAll(() => connectTestDb('tenancy_tests'));
afterAll(() => disconnectTestDb());
beforeEach(async () => {
  await clearDb();
  mailer.clear();
});

const REGISTER = '/api/v1/auth/register';
const LOGIN = '/api/v1/auth/login';

describe('tenant resolution', () => {
  it('rejects requests without a valid tenant API key', async () => {
    expect((await raw.post(LOGIN).send({ email: 'a@b.com', password: 'whatever1' })).status).toBe(401);
    const wrong = await client('not-a-real-key').post(LOGIN).send({ email: 'a@b.com', password: 'whatever1' });
    expect(wrong.status).toBe(401);
    expect(wrong.body.error.message).toBe('Invalid or missing API key');
  });

  it('rejects an X-Tenant-Id that disagrees with the API key', async () => {
    const res = await api.post(LOGIN).set('X-Tenant-Id', 'web_portal').send({ email: 'a@b.com', password: 'whatever1' });
    expect(res.status).toBe(403);
    const ok = await api.post(LOGIN).set('X-Tenant-Id', 'mobile_app').send({ email: 'a@b.com', password: 'whatever1' });
    expect(ok.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('rejects disabled tenants', async () => {
    const res = await client(TEST_KEYS.disabled).post(LOGIN).send({ email: 'a@b.com', password: 'whatever1' });
    expect(res.status).toBe(403);
  });

  it("only accepts browser requests from the tenant's own origins", async () => {
    const fromPortal = await web.post(LOGIN).set('Origin', WEB_ORIGIN).send({ email: 'a@b.com', password: 'whatever1' });
    expect(fromPortal.body.error.code).toBe('INVALID_CREDENTIALS'); // passed the tenant gate

    // The mobile tenant has no browser origins; a page can't use its key from a browser.
    const mobileFromBrowser = await api.post(LOGIN).set('Origin', WEB_ORIGIN).send({ email: 'a@b.com', password: 'whatever1' });
    expect(mobileFromBrowser.status).toBe(403);

    const otherSite = await web.post(LOGIN).set('Origin', 'https://evil.example.com').send({ email: 'a@b.com', password: 'whatever1' });
    expect(otherSite.status).toBe(403);
  });
});

describe('data isolation', () => {
  it('stores each tenant in its own collections', async () => {
    await api.post(REGISTER).send(validUser).expect(201);
    await web.post(REGISTER).send({ ...validUser, email: 'web.only@example.com', phone: '+12125550111' }).expect(201);

    const names = (await mongoose.connection.db!.listCollections().toArray()).map((c) => c.name);
    expect(names).toEqual(expect.arrayContaining(['mobile_app_users', 'web_portal_users', 'mobile_app_refresh_tokens']));

    const db = mongoose.connection.db!;
    expect(await db.collection('mobile_app_users').countDocuments()).toBe(1);
    expect(await db.collection('web_portal_users').countDocuments()).toBe(1);
    expect(await db.collection('mobile_app_users').findOne({ email: 'web.only@example.com' })).toBeNull();
  });

  it('lets the same email and phone register independently in each tenant', async () => {
    const mobile = await api.post(REGISTER).send(validUser);
    const website = await web.post(REGISTER).send(validUser);
    expect(mobile.status).toBe(201);
    expect(website.status).toBe(201);
    expect(mobile.body.user.tenant).toBe('mobile_app');
    expect(website.body.user.tenant).toBe('web_portal');
    expect(mobile.body.user.id).not.toBe(website.body.user.id);

    // Still unique within a tenant.
    expect((await web.post(REGISTER).send(validUser)).status).toBe(409);
  });

  it('keeps credentials separate: an account only logs in on its own tenant', async () => {
    await api.post(REGISTER).send(validUser).expect(201);
    const credentials = { email: validUser.email, password: validUser.password };
    expect((await api.post(LOGIN).send(credentials)).status).toBe(200);
    expect((await web.post(LOGIN).send(credentials)).status).toBe(401);
  });

  it('separate passwords per tenant for the same person', async () => {
    await api.post(REGISTER).send(validUser).expect(201);
    await web.post(REGISTER).send({ ...validUser, password: 'website password', confirmPassword: 'website password' }).expect(201);
    expect((await api.post(LOGIN).send({ email: validUser.email, password: 'website password' })).status).toBe(401);
    expect((await web.post(LOGIN).send({ email: validUser.email, password: 'website password' })).status).toBe(200);
  });
});

describe('cross-tenant token protection', () => {
  it("rejects one tenant's access token on another tenant", async () => {
    const { body } = await api.post(REGISTER).send(validUser).expect(201);
    const auth = `Bearer ${body.tokens.accessToken}`;
    expect((await api.get('/api/v1/auth/me').set('Authorization', auth)).status).toBe(200);
    const cross = await web.get('/api/v1/auth/me').set('Authorization', auth);
    expect(cross.status).toBe(401);
    expect(cross.body.error.code).toBe('INVALID_TOKEN');
  });

  it("rejects one tenant's refresh token on another tenant", async () => {
    const { body } = await api.post(REGISTER).send(validUser).expect(201);
    expect((await web.post('/api/v1/auth/refresh').send({ refreshToken: body.tokens.refreshToken })).status).toBe(401);
    // …and the failed cross-tenant attempt did not consume it.
    expect((await api.post('/api/v1/auth/refresh').send({ refreshToken: body.tokens.refreshToken })).status).toBe(200);
  });

  it('scopes password reset codes to the tenant and brands the email', async () => {
    await api.post(REGISTER).send(validUser).expect(201);
    await web.post(REGISTER).send(validUser).expect(201);

    await web.post('/api/v1/auth/forgot-password').send({ email: validUser.email }).expect(202);
    const message = mailer.lastTo('jane.doe@example.com')!;
    expect(message.from).toBe('Customer Portal <portal@example.com>');
    expect(message.subject).toContain('Customer Portal');
    const code = resetCodeFrom(mailer, 'jane.doe@example.com');

    const body = { email: validUser.email, code, newPassword: 'brand new password', confirmPassword: 'brand new password' };
    // The website's code can't reset the mobile account…
    expect((await api.post('/api/v1/auth/reset-password').send(body)).status).toBe(400);
    // …but works on the website, and only changes the website account.
    expect((await web.post('/api/v1/auth/reset-password').send(body)).status).toBe(200);
    expect((await api.post(LOGIN).send({ email: validUser.email, password: validUser.password })).status).toBe(200);
    expect((await web.post(LOGIN).send({ email: validUser.email, password: 'brand new password' })).status).toBe(200);
  });
});

describe('database-per-tenant strategy', () => {
  it('stores each tenant in its own database when TENANT_ISOLATION=database', async () => {
    const isolated = buildApp({ TENANT_ISOLATION: 'database', TENANT_DB_PREFIX: 'tt_' });
    await isolated.api.post(REGISTER).send(validUser).expect(201);
    await isolated.web.post(REGISTER).send(validUser).expect(201);

    const mobileDb = mongoose.connection.useDb('tt_mobile_app');
    const webDb = mongoose.connection.useDb('tt_web_portal');
    expect(await mobileDb.collection('users').countDocuments()).toBe(1);
    expect(await webDb.collection('users').countDocuments()).toBe(1);
    await mobileDb.dropDatabase();
    await webDb.dropDatabase();
  });

  it('computes physical names for both strategies', () => {
    expect(physicalNames('collection', 'web_portal', 'auth_')).toMatchObject({ database: null, users: 'web_portal_users' });
    expect(physicalNames('database', 'web_portal', 'auth_')).toMatchObject({ database: 'auth_web_portal', users: 'users' });
  });
});

describe('tenant configuration', () => {
  const valid = { id: 'shop_web', name: 'Shop', apiKeyHashes: ['a'.repeat(64)] };

  it('validates ids, key hashes and duplicates', () => {
    expect(() => loadTenantConfigs({ TENANTS_JSON: JSON.stringify({ tenants: [{ ...valid, id: 'Bad-Id' }] }) })).toThrow(/id/);
    expect(() => loadTenantConfigs({ TENANTS_JSON: JSON.stringify({ tenants: [{ ...valid, apiKeyHashes: ['plain-key'] }] }) })).toThrow(/SHA-256/);
    expect(() => loadTenantConfigs({ TENANTS_JSON: JSON.stringify({ tenants: [valid, { ...valid, id: 'other_web' }] }) })).toThrow(/more than one tenant/);
    expect(() => loadTenantConfigs({ TENANTS_JSON: JSON.stringify({ tenants: [valid, valid] }) })).toThrow(/Duplicate tenant id/);
    expect(loadTenantConfigs({ TENANTS_JSON: JSON.stringify({ tenants: [valid] }) })[0]).toMatchObject({ enabled: true, allowedOrigins: [] });
  });
});
