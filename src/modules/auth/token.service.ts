import jwt from 'jsonwebtoken';
import type { Types } from 'mongoose';

import type { Env } from '../../config/env.js';
import { randomToken, sha256, uuid } from '../../lib/crypto.js';
import { AppError } from '../../lib/errors.js';
import { RefreshTokenModel } from './models/refresh-token.model.js';

export interface AccessTokenClaims {
  sub: string;
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

/** Short-lived JWT access tokens + rotating, hashed, opaque refresh tokens. */
export class TokenService {
  constructor(private readonly config: TokenConfig) {}

  signAccessToken(userId: string, tokenVersion: number): string {
    return jwt.sign({ tv: tokenVersion } satisfies Omit<AccessTokenClaims, 'sub'>, this.config.JWT_ACCESS_SECRET, {
      algorithm: 'HS256',
      subject: userId,
      issuer: this.config.JWT_ISSUER,
      audience: this.config.JWT_AUDIENCE,
      expiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS,
      jwtid: uuid(),
    });
  }

  verifyAccessToken(token: string): AccessTokenClaims {
    try {
      const payload = jwt.verify(token, this.config.JWT_ACCESS_SECRET, {
        algorithms: ['HS256'],
        issuer: this.config.JWT_ISSUER,
        audience: this.config.JWT_AUDIENCE,
      });
      if (typeof payload === 'string' || typeof payload.sub !== 'string' || typeof payload.tv !== 'number') {
        throw AppError.unauthorized('Invalid access token', 'INVALID_TOKEN');
      }
      return { sub: payload.sub, tv: payload.tv };
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (e instanceof jwt.TokenExpiredError) throw AppError.unauthorized('Access token expired', 'TOKEN_EXPIRED');
      throw AppError.unauthorized('Invalid access token', 'INVALID_TOKEN');
    }
  }

  /** Issues a new token pair. Pass [family] when rotating so reuse detection can revoke it. */
  async issue(userId: Types.ObjectId, tokenVersion: number, ctx: ClientContext, family = uuid()): Promise<TokenPair> {
    const refreshToken = randomToken(48);
    const expiresAt = new Date(Date.now() + this.config.REFRESH_TOKEN_TTL_DAYS * 86_400_000);
    await RefreshTokenModel.create({
      userId,
      tokenHash: sha256(refreshToken),
      family,
      expiresAt,
      userAgent: ctx.userAgent?.slice(0, 300) ?? null,
      ip: ctx.ip ?? null,
    });
    return {
      tokenType: 'Bearer',
      accessToken: this.signAccessToken(userId.toString(), tokenVersion),
      accessTokenExpiresIn: this.config.ACCESS_TOKEN_TTL_SECONDS,
      refreshToken,
      refreshTokenExpiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Validates and consumes a refresh token. Returns the owning user id and token family.
   * If an already-used token is presented, the whole family is revoked (token theft).
   */
  async consume(refreshToken: string): Promise<{ userId: Types.ObjectId; family: string }> {
    const tokenHash = sha256(refreshToken);
    const now = new Date();
    // Atomically mark as used so two concurrent refreshes cannot both succeed.
    const record = await RefreshTokenModel.findOneAndUpdate(
      { tokenHash, revokedAt: null, expiresAt: { $gt: now } },
      { $set: { revokedAt: now } },
      { returnDocument: 'before' },
    );
    if (record) return { userId: record.userId, family: record.family };

    const reused = await RefreshTokenModel.findOne({ tokenHash });
    if (reused?.revokedAt) {
      await RefreshTokenModel.updateMany({ family: reused.family, revokedAt: null }, { $set: { revokedAt: now } });
    }
    throw AppError.unauthorized('Invalid or expired refresh token', 'INVALID_TOKEN');
  }

  async linkReplacement(oldToken: string, newToken: string): Promise<void> {
    await RefreshTokenModel.updateOne({ tokenHash: sha256(oldToken) }, { $set: { replacedByHash: sha256(newToken) } });
  }

  async revoke(refreshToken: string): Promise<void> {
    await RefreshTokenModel.updateOne(
      { tokenHash: sha256(refreshToken), revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
  }

  async revokeAllForUser(userId: Types.ObjectId): Promise<void> {
    await RefreshTokenModel.updateMany({ userId, revokedAt: null }, { $set: { revokedAt: new Date() } });
  }
}
