import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { DuplicateKeyError, type TenantStore } from '../src/persistence/types.js';
import { DRIVERS, testDriver } from './drivers.js';

/** Contract tests every StorageProvider must pass (same expectations for MongoDB and PostgreSQL). */
describe.each(DRIVERS)('storage contract on %s', (driver) => {
  const db = testDriver(driver, 'storage');
  const storage = db.storage('collection', 'auth_');
  let store: TenantStore;

  beforeAll(async () => {
    await db.start();
    store = await storage.forTenant('contract_t');
  });
  afterAll(() => db.stop());
  beforeEach(() => db.clear());

  const newUser = (n = 1) => ({
    fullName: `User ${n}`,
    email: `user${n}@example.com`,
    country: 'US',
    phone: `+1212555${String(1000 + n)}`,
    passwordHash: '$argon2id$fake',
  });

  it('creates and finds users by id, email and phone', async () => {
    const user = await store.users.create(newUser());
    expect(user.id).toEqual(expect.any(String));
    expect(user.tokenVersion).toBe(0);
    expect((await store.users.findById(user.id))?.email).toBe('user1@example.com');
    expect((await store.users.findByEmail('user1@example.com'))?.id).toBe(user.id);
    expect((await store.users.findByPhone('+12125551001'))?.id).toBe(user.id);
    expect(await store.users.findById('not-a-valid-id')).toBeNull();
  });

  it('maps unique violations to DuplicateKeyError with the field', async () => {
    await store.users.create(newUser(1));
    await expect(store.users.create({ ...newUser(2), email: 'user1@example.com' })).rejects.toMatchObject({ field: 'email' });
    const phoneDup = await store.users.create({ ...newUser(3), phone: '+12125551001' }).catch((e: unknown) => e);
    expect(phoneDup).toBeInstanceOf(DuplicateKeyError);
    expect((phoneDup as DuplicateKeyError).field).toBe('phone');
  });

  it('counts failed logins and locks at the limit', async () => {
    const user = await store.users.create(newUser());
    const lockUntil = new Date(Date.now() + 60_000);
    expect(await store.users.recordFailedLogin(user.id, 3, lockUntil)).toBe(false);
    expect(await store.users.recordFailedLogin(user.id, 3, lockUntil)).toBe(false);
    expect(await store.users.recordFailedLogin(user.id, 3, lockUntil)).toBe(true);
    const locked = await store.users.findById(user.id);
    expect(locked?.failedLoginAttempts).toBe(0);
    expect(locked?.lockUntil?.getTime()).toBe(lockUntil.getTime());
  });

  it('setPassword unlocks and bumps the token version', async () => {
    const user = await store.users.create(newUser());
    await store.users.recordFailedLogin(user.id, 1, new Date(Date.now() + 60_000));
    expect(await store.users.setPassword(user.id, 'new-hash')).toBe(1);
    const updated = await store.users.findById(user.id);
    expect(updated).toMatchObject({ passwordHash: 'new-hash', lockUntil: null, tokenVersion: 1 });
  });

  it('lets exactly one concurrent refresh consume a token', async () => {
    const user = await store.users.create(newUser());
    await store.refreshTokens.create({
      userId: user.id,
      tokenHash: 'a'.repeat(64),
      family: '00000000-0000-4000-8000-000000000001',
      expiresAt: new Date(Date.now() + 60_000),
      userAgent: null,
      ip: null,
    });
    const now = new Date();
    const results = await Promise.all(Array.from({ length: 5 }, () => store.refreshTokens.consumeActive('a'.repeat(64), now)));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect((await store.refreshTokens.findByHash('a'.repeat(64)))?.revokedAt).not.toBeNull();
  });

  it('never allows more reset attempts than the limit, even concurrently', async () => {
    const user = await store.users.create(newUser());
    await store.passwordResets.replace(user.id, 'b'.repeat(64), new Date(Date.now() + 60_000));
    const now = new Date();
    const results = await Promise.all(Array.from({ length: 8 }, () => store.passwordResets.consumeAttempt(user.id, now, 5)));
    expect(results.filter(Boolean)).toHaveLength(5);
  });

  it('ignores expired tokens and codes', async () => {
    const user = await store.users.create(newUser());
    const past = new Date(Date.now() - 1000);
    await store.refreshTokens.create({
      userId: user.id,
      tokenHash: 'c'.repeat(64),
      family: '00000000-0000-4000-8000-000000000002',
      expiresAt: past,
      userAgent: null,
      ip: null,
    });
    await store.passwordResets.replace(user.id, 'd'.repeat(64), past);
    expect(await store.refreshTokens.consumeActive('c'.repeat(64), new Date())).toBeNull();
    expect(await store.passwordResets.consumeAttempt(user.id, new Date(), 5)).toBeNull();
    // PostgreSQL deletes them in the scheduled purge; MongoDB relies on TTL indexes (returns 0).
    const purged = await storage.purgeExpired();
    expect(purged).toBe(driver === 'postgres' ? 2 : 0);
  });

  it('replace() keeps one active reset code per user and resets attempts', async () => {
    const user = await store.users.create(newUser());
    const later = new Date(Date.now() + 60_000);
    await store.passwordResets.replace(user.id, 'e'.repeat(64), later);
    await store.passwordResets.consumeAttempt(user.id, new Date(), 5);
    await store.passwordResets.replace(user.id, 'f'.repeat(64), later);
    const attempt = await store.passwordResets.consumeAttempt(user.id, new Date(), 5);
    expect(attempt).toMatchObject({ codeHash: 'f'.repeat(64), attempts: 1 });
  });

  it('reports health and its driver', async () => {
    expect(storage.driver).toBe(driver);
    expect(await storage.isHealthy()).toBe(true);
  });
});
