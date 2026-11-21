import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { loadEnv } from '../src/config/env.js';
import { buildApp, connectTestDb, disconnectTestDb, validUser } from './helpers.js';

beforeAll(() => connectTestDb('security_tests'));
afterAll(() => disconnectTestDb());

describe('API security', () => {
  it('sets security headers and hides the framework', async () => {
    const { api } = buildApp();
    const res = await api.get('/health/live');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['strict-transport-security']).toBeDefined();
    expect(res.headers['x-request-id']).toEqual(expect.any(String));
  });

  it('marks API responses as non-cacheable', async () => {
    const { api } = buildApp();
    const res = await api.post('/api/v1/auth/login').send({ email: 'a@b.com', password: 'whatever1' });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('requires an API key when API_KEYS is configured', async () => {
    const { api } = buildApp({ API_KEYS: 'key-one,key-two' });
    expect((await api.post('/api/v1/auth/login').send({ email: 'a@b.com', password: 'x' })).status).toBe(401);
    const withKey = await api.post('/api/v1/auth/login').set('X-API-Key', 'key-two').send({ email: 'a@b.com', password: 'whatever1' });
    expect(withKey.status).toBe(401); // passes the key gate, then fails on credentials
    expect(withKey.body.error.code).toBe('INVALID_CREDENTIALS');
    expect((await api.get('/health/live')).status).toBe(200);
  });

  it('only allows configured CORS origins', async () => {
    const { api } = buildApp({ CORS_ORIGINS: 'https://app.example.com' });
    const allowed = await api.get('/health/live').set('Origin', 'https://app.example.com');
    const denied = await api.get('/health/live').set('Origin', 'https://evil.example.com');
    expect(allowed.headers['access-control-allow-origin']).toBe('https://app.example.com');
    expect(denied.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('rate-limits repeated login attempts', async () => {
    const { api } = buildApp({ RATE_LIMIT_ENABLED: 'true' });
    let last = 0;
    for (let i = 0; i < 21; i++) {
      last = (await api.post('/api/v1/auth/login').send({ email: 'victim@example.com', password: 'guess guess' })).status;
    }
    expect(last).toBe(429);
  });

  it('rejects oversized bodies', async () => {
    const { api } = buildApp();
    const res = await api.post('/api/v1/auth/register').send({ ...validUser, fullName: 'a'.repeat(20_000) });
    expect(res.status).toBe(413);
  });

  it('returns JSON 404s', async () => {
    const { api } = buildApp();
    const res = await api.get('/api/v1/nope');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  it('refuses weak or missing secrets at startup', () => {
    expect(() => loadEnv({ ...process.env, JWT_ACCESS_SECRET: 'short' })).toThrow(/JWT_ACCESS_SECRET/);
    expect(() => loadEnv({ ...process.env, MAIL_TRANSPORT: 'gmail', GMAIL_USER: undefined })).toThrow(/GMAIL_USER/);
    expect(() => loadEnv({ ...process.env, NODE_ENV: 'production', MAIL_TRANSPORT: 'console' })).toThrow(/MAIL_TRANSPORT/);
  });
});
