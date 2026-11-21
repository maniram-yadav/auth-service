import argon2 from 'argon2';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { buildApp, clearDb, connectTestDb, disconnectTestDb, resetCodeFrom, validUser } from './helpers.js';

const { api, mailer, tenantModels } = buildApp();

beforeAll(() => connectTestDb('auth_tests'));
afterAll(() => disconnectTestDb());
beforeEach(async () => {
  await clearDb();
  mailer.clear();
});

const register = (overrides: Record<string, unknown> = {}) =>
  api.post('/api/v1/auth/register').send({ ...validUser, ...overrides });

describe('POST /register', () => {
  it('creates a user, normalizes email/phone and returns tokens', async () => {
    const res = await register();
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({
      tenant: 'mobile_app',
      fullName: 'Jane Doe',
      email: 'jane.doe@example.com',
      country: 'US',
      phone: '+14155550123',
    });
    expect(res.body.user).not.toHaveProperty('passwordHash');
    expect(res.body.tokens).toMatchObject({ tokenType: 'Bearer', accessTokenExpiresIn: 900 });
    expect(res.body.tokens.refreshToken).toEqual(expect.any(String));
  });

  it('stores the password as an Argon2id hash, never in plain text', async () => {
    await register();
    const { users } = await tenantModels('mobile_app');
    const stored = await users.findOne({ email: 'jane.doe@example.com' }).select('+passwordHash').lean();
    expect(stored!.passwordHash).toMatch(/^\$argon2id\$/);
    expect(stored!.passwordHash).not.toContain(validUser.password);
    expect(await argon2.verify(stored!.passwordHash, validUser.password)).toBe(true);
  });

  it('rejects passwords shorter than 8 characters', async () => {
    const res = await register({ password: 'short7!', confirmPassword: 'short7!' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(res.body.error.details).toContainEqual({ field: 'password', message: 'Password must be at least 8 characters long' });
  });

  it('rejects mismatched password confirmation', async () => {
    const res = await register({ confirmPassword: 'something else' });
    expect(res.status).toBe(400);
    expect(res.body.error.details).toContainEqual({ field: 'confirmPassword', message: 'Passwords do not match' });
  });

  it('validates email, country, phone and full name', async () => {
    const res = await register({ email: 'not-an-email', country: 'XX', phone: '123', fullName: '<script>' });
    expect(res.status).toBe(400);
    const fields = res.body.error.details.map((d: { field: string }) => d.field);
    expect(fields).toEqual(expect.arrayContaining(['email', 'country', 'phone', 'fullName']));
  });

  it('rejects a phone number that is invalid for the selected country', async () => {
    const res = await register({ country: 'GB', phone: '415 555 0123' });
    expect(res.status).toBe(400);
    expect(res.body.error.details[0].field).toBe('phone');
  });

  it('rejects duplicate email or phone with 409', async () => {
    await register();
    const sameEmail = await register({ phone: '+1 212 555 0199' });
    expect(sameEmail.status).toBe(409);
    expect(sameEmail.body.error.details).toContainEqual({ field: 'email', message: 'This email is already registered' });

    const samePhone = await register({ email: 'other@example.com', phone: '+14155550123' });
    expect(samePhone.status).toBe(409);
    expect(samePhone.body.error.details).toContainEqual({ field: 'phone', message: 'This phone number is already registered' });
  });

  it('rejects unknown fields (mass assignment) and non-JSON bodies', async () => {
    const extra = await register({ tokenVersion: 99, isAdmin: true });
    expect(extra.status).toBe(400);

    const form = await api.post('/api/v1/auth/register').type('form').send('email=a@b.com');
    expect(form.status).toBe(415);
  });

  it('rejects malformed JSON', async () => {
    const res = await api.post('/api/v1/auth/register').set('Content-Type', 'application/json').send('{"email":');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_JSON');
  });
});

describe('POST /login', () => {
  beforeEach(async () => {
    await register();
  });

  it('logs in with email + password (case-insensitive email)', async () => {
    const res = await api.post('/api/v1/auth/login').send({ email: 'JANE.DOE@example.com', password: validUser.password });
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('jane.doe@example.com');
    expect(res.body.tokens.accessToken).toEqual(expect.any(String));
  });

  it('logs in with phone + password in international format', async () => {
    const res = await api.post('/api/v1/auth/login').send({ phone: '+1 415-555-0123', password: validUser.password });
    expect(res.status).toBe(200);
    expect(res.body.user.phone).toBe('+14155550123');
  });

  it('logs in with a national phone number plus country', async () => {
    const res = await api.post('/api/v1/auth/login').send({ phone: '4155550123', country: 'US', password: validUser.password });
    expect(res.status).toBe(200);
  });

  it('returns the same generic error for a wrong password and an unknown account', async () => {
    const wrongPassword = await api.post('/api/v1/auth/login').send({ email: validUser.email, password: 'wrong password' });
    const unknown = await api.post('/api/v1/auth/login').send({ email: 'nobody@example.com', password: 'wrong password' });
    expect(wrongPassword.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrongPassword.body.error.message).toBe(unknown.body.error.message);
    expect(wrongPassword.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('requires exactly one of email or phone', async () => {
    const none = await api.post('/api/v1/auth/login').send({ password: 'x' });
    const both = await api.post('/api/v1/auth/login').send({ email: validUser.email, phone: '+14155550123', password: 'x' });
    expect(none.status).toBe(400);
    expect(both.status).toBe(400);
  });

  it('blocks NoSQL operator injection', async () => {
    const res = await api.post('/api/v1/auth/login').send({ email: { $ne: null }, password: { $ne: null } });
    expect(res.status).toBe(400);
  });

  it('locks the account after 5 failed attempts', async () => {
    for (let i = 0; i < 5; i++) {
      await api.post('/api/v1/auth/login').send({ email: validUser.email, password: 'wrong password' });
    }
    const locked = await api.post('/api/v1/auth/login').send({ email: validUser.email, password: validUser.password });
    expect(locked.status).toBe(423);
    expect(locked.body.error.code).toBe('ACCOUNT_LOCKED');
  });
});

describe('tokens and sessions', () => {
  it('protects /me and accepts a valid access token', async () => {
    const { body } = await register();
    expect((await api.get('/api/v1/auth/me')).status).toBe(401);
    expect((await api.get('/api/v1/auth/me').set('Authorization', 'Bearer not-a-jwt')).status).toBe(401);

    const me = await api.get('/api/v1/auth/me').set('Authorization', `Bearer ${body.tokens.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe('jane.doe@example.com');
  });

  it('rotates refresh tokens and detects reuse of an old one', async () => {
    const { body } = await register();
    const first = body.tokens.refreshToken as string;

    const rotated = await api.post('/api/v1/auth/refresh').send({ refreshToken: first });
    expect(rotated.status).toBe(200);
    const second = rotated.body.tokens.refreshToken as string;
    expect(second).not.toBe(first);

    // Replaying the used token is treated as theft: the whole family is revoked.
    expect((await api.post('/api/v1/auth/refresh').send({ refreshToken: first })).status).toBe(401);
    expect((await api.post('/api/v1/auth/refresh').send({ refreshToken: second })).status).toBe(401);
  });

  it('logout revokes the refresh token', async () => {
    const { body } = await register();
    expect((await api.post('/api/v1/auth/logout').send({ refreshToken: body.tokens.refreshToken })).status).toBe(204);
    expect((await api.post('/api/v1/auth/refresh').send({ refreshToken: body.tokens.refreshToken })).status).toBe(401);
  });

  it('logout-all invalidates existing access tokens', async () => {
    const { body } = await register();
    const auth = `Bearer ${body.tokens.accessToken}`;
    expect((await api.post('/api/v1/auth/logout-all').set('Authorization', auth)).status).toBe(204);
    expect((await api.get('/api/v1/auth/me').set('Authorization', auth)).status).toBe(401);
  });
});

describe('forgot / reset password', () => {
  beforeEach(async () => {
    await register();
  });

  it('emails a 6-digit code and resets the password with it', async () => {
    const login = await api.post('/api/v1/auth/login').send({ email: validUser.email, password: validUser.password });
    const oldAccess = login.body.tokens.accessToken as string;

    const forgot = await api.post('/api/v1/auth/forgot-password').send({ email: 'jane.doe@example.com' });
    expect(forgot.status).toBe(202);
    const code = resetCodeFrom(mailer, 'jane.doe@example.com');
    expect(code).toMatch(/^\d{6}$/);

    const reset = await api.post('/api/v1/auth/reset-password').send({
      email: 'jane.doe@example.com',
      code,
      newPassword: 'brand new password',
      confirmPassword: 'brand new password',
    });
    expect(reset.status).toBe(200);

    // Old password stops working, new one works, old sessions are signed out.
    expect((await api.post('/api/v1/auth/login').send({ email: validUser.email, password: validUser.password })).status).toBe(401);
    expect((await api.post('/api/v1/auth/login').send({ email: validUser.email, password: 'brand new password' })).status).toBe(200);
    expect((await api.get('/api/v1/auth/me').set('Authorization', `Bearer ${oldAccess}`)).status).toBe(401);

    // A confirmation email is sent, and the code can't be reused.
    expect(mailer.lastTo('jane.doe@example.com')?.subject).toMatch(/password was changed/);
    const reuse = await api.post('/api/v1/auth/reset-password').send({
      email: 'jane.doe@example.com',
      code,
      newPassword: 'another password!',
      confirmPassword: 'another password!',
    });
    expect(reuse.status).toBe(400);
  });

  it('responds identically for unknown emails and sends nothing', async () => {
    const res = await api.post('/api/v1/auth/forgot-password').send({ email: 'nobody@example.com' });
    expect(res.status).toBe(202);
    expect(mailer.sent).toHaveLength(0);
  });

  it('enforces the 8-character rule on the new password', async () => {
    await api.post('/api/v1/auth/forgot-password').send({ email: validUser.email });
    const code = resetCodeFrom(mailer, 'jane.doe@example.com');
    const res = await api
      .post('/api/v1/auth/reset-password')
      .send({ email: validUser.email, code, newPassword: 'short', confirmPassword: 'short' });
    expect(res.status).toBe(400);
    expect(res.body.error.details).toContainEqual({ field: 'newPassword', message: 'New password must be at least 8 characters long' });
  });

  it('invalidates the code after 5 wrong guesses', async () => {
    await api.post('/api/v1/auth/forgot-password').send({ email: validUser.email });
    const code = resetCodeFrom(mailer, 'jane.doe@example.com');
    const wrong = code === '000000' ? '111111' : '000000';
    const body = { email: validUser.email, newPassword: 'brand new password', confirmPassword: 'brand new password' };

    for (let i = 0; i < 5; i++) {
      const res = await api.post('/api/v1/auth/reset-password').send({ ...body, code: wrong });
      expect(res.body.error.code).toBe('INVALID_RESET_CODE');
    }
    // Even the right code is now rejected.
    expect((await api.post('/api/v1/auth/reset-password').send({ ...body, code })).status).toBe(400);
  });

  it('stores only an HMAC of the code', async () => {
    await api.post('/api/v1/auth/forgot-password').send({ email: validUser.email });
    const code = resetCodeFrom(mailer, 'jane.doe@example.com');
    const { passwordResets } = await tenantModels('mobile_app');
    const record = await passwordResets.findOne().lean();
    expect(record!.codeHash).not.toContain(code);
    expect(record!.codeHash).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('change password', () => {
  it('requires the current password and returns new tokens', async () => {
    const { body } = await register();
    const auth = `Bearer ${body.tokens.accessToken}`;
    const wrong = await api
      .post('/api/v1/auth/change-password')
      .set('Authorization', auth)
      .send({ currentPassword: 'nope nope', newPassword: 'brand new password', confirmPassword: 'brand new password' });
    expect(wrong.status).toBe(400);

    const ok = await api
      .post('/api/v1/auth/change-password')
      .set('Authorization', auth)
      .send({ currentPassword: validUser.password, newPassword: 'brand new password', confirmPassword: 'brand new password' });
    expect(ok.status).toBe(200);
    expect((await api.get('/api/v1/auth/me').set('Authorization', auth)).status).toBe(401);
    expect((await api.get('/api/v1/auth/me').set('Authorization', `Bearer ${ok.body.tokens.accessToken}`)).status).toBe(200);
  });
});
