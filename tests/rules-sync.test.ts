import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { DRIVERS, testDriver } from './drivers.js';
import { buildApp, validUser } from './helpers.js';

const rule = (pattern: string, type = 'PREFIX', extra: Record<string, unknown> = {}) => ({
  type,
  countryIso: 'US',
  anyCountry: false,
  pattern,
  label: null,
  enabled: true,
  ...extra,
});

describe.each(DRIVERS)('rule sync on %s', (driver) => {
  const db = testDriver(driver, 'rulesync');
  const { api, web } = buildApp(db);

  beforeAll(() => db.start());
  afterAll(() => db.stop());
  beforeEach(() => db.clear());

  async function signUp(client = api, overrides: Record<string, string> = {}) {
    const res = await client.post('/api/v1/auth/register').send({ ...validUser, ...overrides }).expect(201);
    return `Bearer ${res.body.tokens.accessToken}`;
  }
  const sync = (auth: string, mode: 'merge' | 'replace', rules: object[], client = api) =>
    client.post('/api/v1/sync/rules').set('Authorization', auth).send({ mode, rules });

  it('uploads the phone rules after sign-up and returns the account rules', async () => {
    const auth = await signUp();
    const res = await sync(auth, 'merge', [rule('800'), rule('0000', 'SUFFIX', { label: 'Spam' })]).expect(200);
    expect(res.body.rules).toHaveLength(2);
    const stored = await api.get('/api/v1/sync/rules').set('Authorization', auth).expect(200);
    expect(stored.body.rules).toEqual(res.body.rules);
    expect(Date.parse(stored.body.updatedAt)).toBeGreaterThan(0);
  });

  it('merge unions server + device rules (new phone restores the account rules)', async () => {
    const auth = await signUp();
    await sync(auth, 'merge', [rule('800'), rule('2125550147', 'EXACT')]).expect(200);
    const res = await sync(auth, 'merge', [rule('555', 'CONTAINS'), rule('8 0 0')]).expect(200);
    const patterns = res.body.rules.map((r: { pattern: string }) => r.pattern).sort();
    // "8 0 0" is the same rule as "800" (same type, country and digits) — the device version wins.
    expect(patterns).toEqual(['2125550147', '555', '8 0 0']);
  });

  it('replace makes the account match the phone (deletions sync)', async () => {
    const auth = await signUp();
    await sync(auth, 'merge', [rule('800'), rule('900')]).expect(200);
    const res = await sync(auth, 'replace', [rule('900', 'PREFIX', { enabled: false })]).expect(200);
    expect(res.body.rules).toEqual([rule('900', 'PREFIX', { enabled: false })]);
  });

  it('validates rules and requires authentication', async () => {
    const auth = await signUp();
    await api.post('/api/v1/sync/rules').send({ mode: 'merge', rules: [] }).expect(401);
    await sync(auth, 'merge', [rule('80a')]).expect(400);
    await sync(auth, 'merge', [{ ...rule('800'), type: 'REGEX' }]).expect(400);
    await sync(auth, 'merge', [{ ...rule('800'), extra: true }]).expect(400);
    await sync(auth, 'merge', Array.from({ length: 2001 }, (_, i) => rule(String(1000 + i)))).expect(400);
  });

  it('keeps each account and tenant separate', async () => {
    const a = await signUp();
    const b = await signUp(api, { email: 'second@example.com', phone: '+12125550190' });
    const w = await signUp(web);
    await sync(a, 'merge', [rule('800')]).expect(200);
    expect((await api.get('/api/v1/sync/rules').set('Authorization', b)).body.rules).toEqual([]);
    expect((await web.get('/api/v1/sync/rules').set('Authorization', w)).body.rules).toEqual([]);
  });
});
