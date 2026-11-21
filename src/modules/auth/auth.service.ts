import type { Logger } from 'pino';

import type { Env } from '../../config/env.js';
import { hmacSha256, numericCode, safeEqual } from '../../lib/crypto.js';
import { AppError, type ErrorDetail } from '../../lib/errors.js';
import { maskEmail } from '../../lib/phone.js';
import { DuplicateKeyError } from '../../persistence/types.js';
import type { TenantContext } from '../../tenancy/tenant-registry.js';
import type { Mailer, MailMessage } from '../mail/mailer.js';
import { passwordChangedEmail, passwordResetCodeEmail } from '../mail/templates.js';
import { toPublicUser, type PublicUser } from '../users/user.js';
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
const DUPLICATE_MESSAGE = {
  email: 'This email is already registered',
  phone: 'This phone number is already registered',
} as const;

/**
 * Registration, login, token refresh and password reset use-cases.
 * Storage-agnostic: it only uses the tenant's repositories (MongoDB or PostgreSQL), so accounts,
 * sessions and reset codes never cross tenant boundaries.
 */
export class AuthService {
  constructor(private readonly deps: AuthServiceDeps) {}

  // ---------------------------------------------------------------- registration

  async register(tenant: TenantContext, input: RegisterInput, ctx: ClientContext): Promise<AuthResult> {
    const { users } = tenant.store;
    const conflicts = await users.findConflicts(input.email, input.phone);
    const details: ErrorDetail[] = [];
    if (conflicts.email) details.push({ field: 'email', message: DUPLICATE_MESSAGE.email });
    if (conflicts.phone) details.push({ field: 'phone', message: DUPLICATE_MESSAGE.phone });
    if (details.length) throw AppError.conflict('An account with these details already exists', details);

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
      // Two concurrent registrations can pass the pre-check; the unique constraint is the real guard.
      if (e instanceof DuplicateKeyError) {
        throw AppError.conflict('An account with these details already exists', [
          { field: e.field, message: DUPLICATE_MESSAGE[e.field] },
        ]);
      }
      throw e;
    }

    this.deps.logger.info({ tenant: tenant.id, userId: user.id, email: maskEmail(user.email) }, 'user registered');
    const tokens = await this.deps.tokens.issue(tenant, user.id, user.tokenVersion, ctx);
    return { user: toPublicUser(tenant.id, user), tokens };
  }

  // ---------------------------------------------------------------- login

  async login(tenant: TenantContext, input: LoginInput, ctx: ClientContext): Promise<AuthResult> {
    const { users } = tenant.store;
    const user = input.kind === 'email' ? await users.findByEmail(input.email) : await users.findByPhone(input.phone);

    if (!user) {
      await this.deps.passwords.verifyDummy(input.password);
      throw AppError.unauthorized(INVALID_CREDENTIALS, 'INVALID_CREDENTIALS');
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      throw new AppError(423, 'ACCOUNT_LOCKED', 'Too many failed sign-in attempts. Try again later or reset your password.');
    }

    if (!(await this.deps.passwords.verify(user.passwordHash, input.password))) {
      const { LOGIN_MAX_FAILED_ATTEMPTS, LOGIN_LOCK_MINUTES } = this.deps.config;
      const locked = await users.recordFailedLogin(
        user.id,
        LOGIN_MAX_FAILED_ATTEMPTS,
        new Date(Date.now() + LOGIN_LOCK_MINUTES * 60_000),
      );
      if (locked) this.deps.logger.warn({ tenant: tenant.id, userId: user.id }, 'account temporarily locked after failed logins');
      throw AppError.unauthorized(INVALID_CREDENTIALS, 'INVALID_CREDENTIALS');
    }

    const upgraded = this.deps.passwords.needsRehash(user.passwordHash)
      ? await this.deps.passwords.hash(input.password)
      : undefined;
    await users.recordSuccessfulLogin(user.id, upgraded);

    const tokens = await this.deps.tokens.issue(tenant, user.id, user.tokenVersion, ctx);
    return { user: toPublicUser(tenant.id, user), tokens };
  }

  // ---------------------------------------------------------------- sessions

  async refresh(tenant: TenantContext, refreshToken: string, ctx: ClientContext): Promise<TokenPair> {
    const { userId, family } = await this.deps.tokens.consume(tenant, refreshToken);
    const tokenVersion = await tenant.store.users.getTokenVersion(userId);
    if (tokenVersion === null) throw AppError.unauthorized('Invalid or expired refresh token', 'INVALID_TOKEN');
    const tokens = await this.deps.tokens.issue(tenant, userId, tokenVersion, ctx, family);
    await this.deps.tokens.linkReplacement(tenant, refreshToken, tokens.refreshToken);
    return tokens;
  }

  async logout(tenant: TenantContext, refreshToken: string): Promise<void> {
    await this.deps.tokens.revoke(tenant, refreshToken);
  }

  /** Signs the user out everywhere: invalidates access tokens and revokes refresh tokens. */
  async logoutAll(tenant: TenantContext, userId: string): Promise<void> {
    if (await tenant.store.users.bumpTokenVersion(userId)) await this.deps.tokens.revokeAllForUser(tenant, userId);
  }

  async me(tenant: TenantContext, userId: string): Promise<PublicUser> {
    const user = await tenant.store.users.findById(userId);
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
    const { users, passwordResets } = tenant.store;
    const user = await users.findByEmail(email);
    if (!user) return;

    const { RESET_CODE_RESEND_COOLDOWN_SECONDS, RESET_CODE_TTL_MINUTES } = this.deps.config;
    const lastSent = await passwordResets.findCreatedAt(user.id);
    if (lastSent && Date.now() - lastSent.getTime() < RESET_CODE_RESEND_COOLDOWN_SECONDS * 1000) {
      return; // Recently sent: don't spam the inbox.
    }

    const code = numericCode(6);
    await passwordResets.replace(user.id, this.codeHash(tenant, code), new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60_000));

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
    const { users, passwordResets } = tenant.store;
    const { RESET_CODE_MAX_ATTEMPTS } = this.deps.config;
    const user = await users.findByEmail(input.email);
    if (!user) throw new AppError(400, 'INVALID_RESET_CODE', INVALID_RESET_CODE);

    // Atomically count the attempt first, so parallel guesses can't exceed the limit.
    const attempt = await passwordResets.consumeAttempt(user.id, new Date(), RESET_CODE_MAX_ATTEMPTS);
    if (!attempt) throw new AppError(400, 'INVALID_RESET_CODE', INVALID_RESET_CODE);

    if (!safeEqual(this.codeHash(tenant, input.code), attempt.codeHash)) {
      if (attempt.attempts >= RESET_CODE_MAX_ATTEMPTS) await passwordResets.delete(attempt.id);
      throw new AppError(400, 'INVALID_RESET_CODE', INVALID_RESET_CODE);
    }

    if (await this.deps.passwords.verify(user.passwordHash, input.newPassword)) {
      throw AppError.badRequest('New password must be different from the current password', [
        { field: 'newPassword', message: 'New password must be different from the current password' },
      ]);
    }

    await this.setPassword(tenant, user.id, input.newPassword);
    await passwordResets.deleteForUser(user.id);
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
    const user = await tenant.store.users.findById(userId);
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
    const tokenVersion = await this.setPassword(tenant, user.id, input.newPassword);
    this.sendInBackground(
      tenant,
      passwordChangedEmail({ to: user.email, name: user.fullName, appName: this.appName(tenant) }),
      'password changed',
    );
    return this.deps.tokens.issue(tenant, user.id, tokenVersion, ctx);
  }

  /** Stores a new hash, unlocks the account and invalidates every existing session. */
  private async setPassword(tenant: TenantContext, userId: string, password: string): Promise<number> {
    const tokenVersion = await tenant.store.users.setPassword(userId, await this.deps.passwords.hash(password));
    await this.deps.tokens.revokeAllForUser(tenant, userId);
    return tokenVersion;
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
