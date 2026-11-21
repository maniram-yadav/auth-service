import mongoose, { type Types } from 'mongoose';
import type { Logger } from 'pino';

import type { Env } from '../../config/env.js';
import { hmacSha256, numericCode, safeEqual } from '../../lib/crypto.js';
import { AppError, type ErrorDetail } from '../../lib/errors.js';
import { maskEmail } from '../../lib/phone.js';
import type { TenantContext } from '../../tenancy/tenant-registry.js';
import type { Mailer, MailMessage } from '../mail/mailer.js';
import { passwordChangedEmail, passwordResetCodeEmail } from '../mail/templates.js';
import { toPublicUser, type PublicUser } from '../users/user.model.js';
import type { ChangePasswordInput, LoginInput, RegisterInput, ResetPasswordInput } from './auth.schemas.js';
import type { PasswordService } from './password.service.js';
import type { ClientContext, TokenPair, TokenService } from './token.service.js';

export interface AuthResult {
  user: PublicUser;
  tokens: TokenPair;
}

type AuthConfig = Pick<
  Env,
  | 'APP_NAME'
  | 'LOGIN_MAX_FAILED_ATTEMPTS'
  | 'LOGIN_LOCK_MINUTES'
  | 'RESET_CODE_SECRET'
  | 'RESET_CODE_TTL_MINUTES'
  | 'RESET_CODE_MAX_ATTEMPTS'
  | 'RESET_CODE_RESEND_COOLDOWN_SECONDS'
>;

export interface AuthServiceDeps {
  config: AuthConfig;
  passwords: PasswordService;
  tokens: TokenService;
  mailer: Mailer;
  logger: Logger;
}

const INVALID_CREDENTIALS = 'Invalid credentials';
const INVALID_RESET_CODE = 'Invalid or expired reset code';

const isDuplicateKeyError = (e: unknown): e is { code: number; keyPattern?: Record<string, unknown> } =>
  typeof e === 'object' && e !== null && (e as { code?: unknown }).code === 11000;

/**
 * Registration, login, token refresh and password reset use-cases.
 * Every method receives the request's TenantContext and only touches that tenant's
 * collections, so accounts, sessions and reset codes never cross tenant boundaries.
 */
export class AuthService {
  constructor(private readonly deps: AuthServiceDeps) {}

  // ---------------------------------------------------------------- registration

  async register(tenant: TenantContext, input: RegisterInput, ctx: ClientContext): Promise<AuthResult> {
    const { users } = tenant.models;
    const conflicts = await this.findConflicts(tenant, input.email, input.phone);
    if (conflicts.length) throw AppError.conflict('An account with these details already exists', conflicts);

    const passwordHash = await this.deps.passwords.hash(input.password);
    let user;
    try {
      user = await users.create({
        fullName: input.fullName,
        email: input.email,
        country: input.country,
        phone: input.phone,
        passwordHash,
      });
    } catch (e) {
      // Two concurrent registrations can pass the pre-check; the unique index is the real guard.
      if (isDuplicateKeyError(e)) {
        const field = Object.keys(e.keyPattern ?? {})[0] ?? 'email';
        throw AppError.conflict('An account with these details already exists', [
          { field, message: `This ${field} is already registered` },
        ]);
      }
      throw e;
    }

    this.deps.logger.info({ tenant: tenant.id, userId: user.id, email: maskEmail(user.email) }, 'user registered');
    const tokens = await this.deps.tokens.issue(tenant, user._id, user.tokenVersion, ctx);
    return { user: toPublicUser(tenant.id, user), tokens };
  }

  private async findConflicts(tenant: TenantContext, email: string, phone: string): Promise<ErrorDetail[]> {
    const existing = await tenant.models.users.find({ $or: [{ email }, { phone }] }, { email: 1, phone: 1 }).lean();
    const details: ErrorDetail[] = [];
    if (existing.some((u) => u.email === email)) details.push({ field: 'email', message: 'This email is already registered' });
    if (existing.some((u) => u.phone === phone)) details.push({ field: 'phone', message: 'This phone number is already registered' });
    return details;
  }

  // ---------------------------------------------------------------- login

  async login(tenant: TenantContext, input: LoginInput, ctx: ClientContext): Promise<AuthResult> {
    const { users } = tenant.models;
    const filter = input.kind === 'email' ? { email: input.email } : { phone: input.phone };
    const user = await users.findOne(filter).select('+passwordHash');

    if (!user) {
      await this.deps.passwords.verifyDummy(input.password);
      throw AppError.unauthorized(INVALID_CREDENTIALS, 'INVALID_CREDENTIALS');
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      throw new AppError(423, 'ACCOUNT_LOCKED', 'Too many failed sign-in attempts. Try again later or reset your password.');
    }

    const valid = await this.deps.passwords.verify(user.passwordHash, input.password);
    if (!valid) {
      await this.recordFailedLogin(tenant, user._id);
      throw AppError.unauthorized(INVALID_CREDENTIALS, 'INVALID_CREDENTIALS');
    }

    const update: Record<string, unknown> = { failedLoginAttempts: 0, lockUntil: null, lastLoginAt: new Date() };
    if (this.deps.passwords.needsRehash(user.passwordHash)) {
      update.passwordHash = await this.deps.passwords.hash(input.password);
    }
    await users.updateOne({ _id: user._id }, { $set: update });

    const tokens = await this.deps.tokens.issue(tenant, user._id, user.tokenVersion, ctx);
    return { user: toPublicUser(tenant.id, user), tokens };
  }

  private async recordFailedLogin(tenant: TenantContext, userId: Types.ObjectId): Promise<void> {
    const { users } = tenant.models;
    const { LOGIN_MAX_FAILED_ATTEMPTS, LOGIN_LOCK_MINUTES } = this.deps.config;
    const updated = await users.findOneAndUpdate(
      { _id: userId },
      { $inc: { failedLoginAttempts: 1 } },
      { returnDocument: 'after', projection: { failedLoginAttempts: 1 } },
    );
    if (updated && updated.failedLoginAttempts >= LOGIN_MAX_FAILED_ATTEMPTS) {
      await users.updateOne(
        { _id: userId },
        { $set: { failedLoginAttempts: 0, lockUntil: new Date(Date.now() + LOGIN_LOCK_MINUTES * 60_000) } },
      );
      this.deps.logger.warn({ tenant: tenant.id, userId: userId.toString() }, 'account temporarily locked after failed logins');
    }
  }

  // ---------------------------------------------------------------- sessions

  async refresh(tenant: TenantContext, refreshToken: string, ctx: ClientContext): Promise<TokenPair> {
    const { userId, family } = await this.deps.tokens.consume(tenant, refreshToken);
    const user = await tenant.models.users.findById(userId, { tokenVersion: 1 });
    if (!user) throw AppError.unauthorized('Invalid or expired refresh token', 'INVALID_TOKEN');
    const tokens = await this.deps.tokens.issue(tenant, user._id, user.tokenVersion, ctx, family);
    await this.deps.tokens.linkReplacement(tenant, refreshToken, tokens.refreshToken);
    return tokens;
  }

  async logout(tenant: TenantContext, refreshToken: string): Promise<void> {
    await this.deps.tokens.revoke(tenant, refreshToken);
  }

  /** Signs the user out everywhere: invalidates access tokens and revokes refresh tokens. */
  async logoutAll(tenant: TenantContext, userId: string): Promise<void> {
    const user = await tenant.models.users.findByIdAndUpdate(userId, { $inc: { tokenVersion: 1 } });
    if (user) await this.deps.tokens.revokeAllForUser(tenant, user._id);
  }

  async me(tenant: TenantContext, userId: string): Promise<PublicUser> {
    const user = await tenant.models.users.findById(userId);
    if (!user) throw AppError.notFound('User not found');
    return toPublicUser(tenant.id, user);
  }

  // ---------------------------------------------------------------- forgot / reset password

  /** Reset codes are bound to the tenant (domain-separated HMAC) so a code can't be reused elsewhere. */
  private codeHash(tenant: TenantContext, code: string): string {
    return hmacSha256(`${tenant.id}:${code}`, this.deps.config.RESET_CODE_SECRET);
  }

  /**
   * Emails a 6-digit reset code. Always resolves the same way whether or not the email is
   * registered, and the mail is sent in the background, so responses can't reveal accounts.
   */
  async forgotPassword(tenant: TenantContext, email: string): Promise<void> {
    const { users, passwordResets } = tenant.models;
    const user = await users.findOne({ email }, { fullName: 1, email: 1 });
    if (!user) return;

    const { RESET_CODE_RESEND_COOLDOWN_SECONDS, RESET_CODE_TTL_MINUTES } = this.deps.config;
    const existing = await passwordResets.findOne({ userId: user._id }, { createdAt: 1 });
    if (existing && Date.now() - existing.createdAt.getTime() < RESET_CODE_RESEND_COOLDOWN_SECONDS * 1000) {
      return; // Recently sent: don't spam the inbox.
    }

    const code = numericCode(6);
    await passwordResets.deleteMany({ userId: user._id });
    await passwordResets.create({
      userId: user._id,
      codeHash: this.codeHash(tenant, code),
      attempts: 0,
      expiresAt: new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60_000),
    });

    this.sendInBackground(
      tenant,
      passwordResetCodeEmail({
        to: user.email,
        name: user.fullName,
        code,
        ttlMinutes: RESET_CODE_TTL_MINUTES,
        appName: this.appName(tenant),
      }),
      'password reset code',
    );
  }

  async resetPassword(tenant: TenantContext, input: ResetPasswordInput): Promise<void> {
    const { users, passwordResets } = tenant.models;
    const { RESET_CODE_MAX_ATTEMPTS } = this.deps.config;
    const user = await users.findOne({ email: input.email }).select('+passwordHash');
    if (!user) throw new AppError(400, 'INVALID_RESET_CODE', INVALID_RESET_CODE);

    // Atomically count the attempt first, so parallel guesses can't exceed the limit.
    const reset = await passwordResets.findOneAndUpdate(
      {
        userId: user._id,
        // Server-built operators; trusted() exempts them from the global sanitizeFilter.
        expiresAt: mongoose.trusted({ $gt: new Date() }),
        attempts: mongoose.trusted({ $lt: RESET_CODE_MAX_ATTEMPTS }),
      },
      { $inc: { attempts: 1 } },
      { returnDocument: 'after' },
    );
    if (!reset) throw new AppError(400, 'INVALID_RESET_CODE', INVALID_RESET_CODE);

    if (!safeEqual(this.codeHash(tenant, input.code), reset.codeHash)) {
      if (reset.attempts >= RESET_CODE_MAX_ATTEMPTS) await passwordResets.deleteOne({ _id: reset._id });
      throw new AppError(400, 'INVALID_RESET_CODE', INVALID_RESET_CODE);
    }

    if (await this.deps.passwords.verify(user.passwordHash, input.newPassword)) {
      throw AppError.badRequest('New password must be different from the current password', [
        { field: 'newPassword', message: 'New password must be different from the current password' },
      ]);
    }

    await this.setPassword(tenant, user._id, input.newPassword);
    await passwordResets.deleteMany({ userId: user._id });
    this.deps.logger.info({ tenant: tenant.id, userId: user.id }, 'password reset completed');
    this.sendInBackground(
      tenant,
      passwordChangedEmail({ to: user.email, name: user.fullName, appName: this.appName(tenant) }),
      'password changed',
    );
  }

  /** Authenticated password change. Signs out other sessions and returns fresh tokens. */
  async changePassword(
    tenant: TenantContext,
    userId: string,
    input: ChangePasswordInput,
    ctx: ClientContext,
  ): Promise<TokenPair> {
    const user = await tenant.models.users.findById(userId).select('+passwordHash');
    if (!user) throw AppError.unauthorized();
    if (!(await this.deps.passwords.verify(user.passwordHash, input.currentPassword))) {
      throw AppError.badRequest('Current password is incorrect', [
        { field: 'currentPassword', message: 'Current password is incorrect' },
      ]);
    }
    if (input.currentPassword === input.newPassword) {
      throw AppError.badRequest('New password must be different from the current password', [
        { field: 'newPassword', message: 'New password must be different from the current password' },
      ]);
    }
    const tokenVersion = await this.setPassword(tenant, user._id, input.newPassword);
    this.sendInBackground(
      tenant,
      passwordChangedEmail({ to: user.email, name: user.fullName, appName: this.appName(tenant) }),
      'password changed',
    );
    return this.deps.tokens.issue(tenant, user._id, tokenVersion, ctx);
  }

  /** Stores a new hash, unlocks the account and invalidates every existing session. */
  private async setPassword(tenant: TenantContext, userId: Types.ObjectId, password: string): Promise<number> {
    const passwordHash = await this.deps.passwords.hash(password);
    const updated = await tenant.models.users.findOneAndUpdate(
      { _id: userId },
      {
        $set: { passwordHash, passwordChangedAt: new Date(), failedLoginAttempts: 0, lockUntil: null },
        $inc: { tokenVersion: 1 },
      },
      { returnDocument: 'after', projection: { tokenVersion: 1 } },
    );
    await this.deps.tokens.revokeAllForUser(tenant, userId);
    return updated?.tokenVersion ?? 0;
  }

  private appName(tenant: TenantContext): string {
    return tenant.config.mail.appName ?? this.deps.config.APP_NAME;
  }

  private sendInBackground(tenant: TenantContext, message: MailMessage, kind: string): void {
    const branded: MailMessage = tenant.config.mail.from ? { ...message, from: tenant.config.mail.from } : message;
    this.deps.mailer.send(branded).catch((error: unknown) => {
      this.deps.logger.error({ err: error, tenant: tenant.id, to: maskEmail(message.to) }, `failed to send ${kind} email`);
    });
  }
}
