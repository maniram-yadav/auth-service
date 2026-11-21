import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { loadEnv } from '../src/config/env.js';
import { DRIVERS, testDriver } from './drivers.js';
import { buildApp, validUser } from './helpers.js';

describe.each(DRIVERS)('security on %s', (driver) => {
  const db = testDriver(driver, 'security');
  beforeAll(() => db.start());
  afterAll(() => db.stop());

  describe('API security', () => {
    it('sets security headers and hides the framework', async () => {
      const { raw } = buildApp(db);
      const res = await raw.get('/health/live');
      expect(res.headers['x-powered-by']).toBeUndefined();
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['strict-transport-security']).toBeDefined();
      expect(res.headers['x-request-id']).toEqual(expect.any(String));
    });

    it('marks API responses as non-cacheable', async () => {
      const { api } = buildApp(db);
      const res = await api.post('/api/v1/auth/login').send({ email: 'a@b.com', password: 'whatever1' });
      expect(res.headers['cache-control']).toBe('no-store');
    });

    it('only allows configured CORS origins (env + tenant origins)', async () => {
      const { raw } = buildApp(db, { CORS_ORIGINS: 'https://app.example.com' });
      const allowed = await raw.get('/health/live').set('Origin', 'https://app.example.com');
      const tenantOrigin = await raw.get('/health/live').set('Origin', 'https://portal.example.com');
      const denied = await raw.get('/health/live').set('Origin', 'https://evil.example.com');
      expect(allowed.headers['access-control-allow-origin']).toBe('https://app.example.com');
      expect(tenantOrigin.headers['access-control-allow-origin']).toBe('https://portal.example.com');
      expect(denied.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('rate-limits repeated login attempts', async () => {
      const { api } = buildApp(db, { RATE_LIMIT_ENABLED: 'true' });
      let last = 0;
      for (let i = 0; i < 21; i++) {
        last = (await api.post('/api/v1/auth/login').send({ email: 'victim@example.com', password: 'guess guess' })).status;
      }
      expect(last).toBe(429);
    });

    it('rejects oversized bodies', async () => {
      const { api } = buildApp(db);
      const res = await api.post('/api/v1/auth/register').send({ ...validUser, fullName: 'a'.repeat(20_000) });
      expect(res.status).toBe(413);
    });

    it('returns JSON 404s', async () => {
      const { api } = buildApp(db);
      const res = await api.get('/api/v1/nope');
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('refuses weak or missing secrets at startup', () => {
      expect(() => loadEnv({ ...process.env, JWT_ACCESS_SECRET: 'short' })).toThrow(/JWT_ACCESS_SECRET/);
      expect(() => loadEnv({ ...process.env, MAIL_TRANSPORT: 'gmail', GMAIL_USER: undefined })).toThrow(/GMAIL_USER/);
      expect(() => loadEnv({ ...process.env, NODE_ENV: 'production', MAIL_TRANSPORT: 'console' })).toThrow(/MAIL_TRANSPORT/);
      expect(() => loadEnv({ ...process.env, TENANTS_JSON: undefined, TENANTS_FILE: undefined })).toThrow(/TENANTS_FILE/);
    });
  });
});
