import jwt from 'jsonwebtoken';
import mongoose, { type Types } from 'mongoose';

import type { Env } from '../../config/env.js';
import { randomToken, sha256, uuid } from '../../lib/crypto.js';
import { AppError } from '../../lib/errors.js';
import type { TenantContext } from '../../tenancy/tenant-registry.js';

export interface AccessTokenClaims {
  sub: string;
  /** Tenant the token was issued for; must match the tenant of the request. */
  tid: string;
  /** Must equal the user's current tokenVersion. */
  tv: number;
}

export interface TokenPair {
  tokenType: 'Bearer';
  accessToken: string;
  accessTokenExpiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export interface ClientContext {
  userAgent?: string | null;
  ip?: string | null;
}

type TokenConfig = Pick<
  Env,
  'JWT_ACCESS_SECRET' | 'JWT_ISSUER' | 'JWT_AUDIENCE' | 'ACCESS_TOKEN_TTL_SECONDS' | 'REFRESH_TOKEN_TTL_DAYS'
>;

/**
 * Short-lived JWT access tokens + rotating, hashed, opaque refresh tokens.
 * Access tokens carry the tenant id; refresh tokens live in the tenant's own collection,
 * so neither can be replayed against another tenant.
 */
export class TokenService {
  constructor(private readonly config: TokenConfig) {}

  private audience(tenantId: string): string {
    return `${this.config.JWT_AUDIENCE}:${tenantId}`;
  }

  signAccessToken(tenantId: string, userId: string, tokenVersion: number): string {
    return jwt.sign({ tid: tenantId, tv: tokenVersion }, this.config.JWT_ACCESS_SECRET, {
      algorithm: 'HS256',
      subject: userId,
      issuer: this.config.JWT_ISSUER,
      audience: this.audience(tenantId),
      expiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS,
      jwtid: uuid(),
    });
  }

  /** Verifies signature, expiry, issuer and that the token belongs to [tenantId]. */
  verifyAccessToken(token: string, tenantId: string): AccessTokenClaims {
    try {
      const payload = jwt.verify(token, this.config.JWT_ACCESS_SECRET, {
        algorithms: ['HS256'],
        issuer: this.config.JWT_ISSUER,
        audience: this.audience(tenantId),
      });
      if (
        typeof payload === 'string' ||
        typeof payload.sub !== 'string' ||
        typeof payload.tv !== 'number' ||
        payload.tid !== tenantId
      ) {
        throw AppError.unauthorized('Invalid access token', 'INVALID_TOKEN');
      }
      return { sub: payload.sub, tid: payload.tid, tv: payload.tv };
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (e instanceof jwt.TokenExpiredError) throw AppError.unauthorized('Access token expired', 'TOKEN_EXPIRED');
      throw AppError.unauthorized('Invalid access token', 'INVALID_TOKEN');
    }
  }

  /** Issues a new token pair. Pass [family] when rotating so reuse detection can revoke it. */
  async issue(
    tenant: TenantContext,
    userId: Types.ObjectId,
    tokenVersion: number,
    ctx: ClientContext,
    family = uuid(),
  ): Promise<TokenPair> {
    const refreshToken = randomToken(48);
    const expiresAt = new Date(Date.now() + this.config.REFRESH_TOKEN_TTL_DAYS * 86_400_000);
    await tenant.models.refreshTokens.create({
      userId,
      tokenHash: sha256(refreshToken),
      family,
      expiresAt,
      userAgent: ctx.userAgent?.slice(0, 300) ?? null,
      ip: ctx.ip ?? null,
    });
    return {
      tokenType: 'Bearer',
      accessToken: this.signAccessToken(tenant.id, userId.toString(), tokenVersion),
      accessTokenExpiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS,
      refreshToken,
      refreshTokenExpiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Validates and consumes a refresh token. Returns the owning user id and token family.
   * If an already-used token is presented, the whole family is revoked (token theft).
   */
  async consume(tenant: TenantContext, refreshToken: string): Promise<{ userId: Types.ObjectId; family: string }> {
    const { refreshTokens } = tenant.models;
    const tokenHash = sha256(refreshToken);
    const now = new Date();
    // Atomically mark as used so two concurrent refreshes cannot both succeed.
    // mongoose.trusted(): our own operator, exempt from the global sanitizeFilter.
    const record = await refreshTokens.findOneAndUpdate(
      { tokenHash, revokedAt: null, expiresAt: mongoose.trusted({ $gt: now }) },
      { $set: { revokedAt: now } },
      { returnDocument: 'before' },
    );
    if (record) return { userId: record.userId, family: record.family };

    const reused = await refreshTokens.findOne({ tokenHash });
    if (reused?.revokedAt) {
      await refreshTokens.updateMany({ family: reused.family, revokedAt: null }, { $set: { revokedAt: now } });
    }
    throw AppError.unauthorized('Invalid or expired refresh token', 'INVALID_TOKEN');
  }

  async linkReplacement(tenant: TenantContext, oldToken: string, newToken: string): Promise<void> {
    await tenant.models.refreshTokens.updateOne(
      { tokenHash: sha256(oldToken) },
      { $set: { replacedByHash: sha256(newToken) } },
    );
  }

  async revoke(tenant: TenantContext, refreshToken: string): Promise<void> {
    await tenant.models.refreshTokens.updateOne(
      { tokenHash: sha256(refreshToken), revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
  }

  async revokeAllForUser(tenant: TenantContext, userId: Types.ObjectId): Promise<void> {
    await tenant.models.refreshTokens.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: new Date() } });
  }
}
