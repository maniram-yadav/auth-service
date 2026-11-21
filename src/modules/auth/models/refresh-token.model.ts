import { Schema, type Types } from 'mongoose';

/**
 * Opaque refresh tokens. Only a SHA-256 hash is stored. Tokens rotate on every use; all
 * tokens from one login share a `family`, so a replayed (already used) token revokes the family.
 */
export interface RefreshToken {
  userId: Types.ObjectId;
  tokenHash: string;
  family: string;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedByHash: string | null;
  userAgent: string | null;
  ip: string | null;
  createdAt: Date;
}

export const refreshTokenSchema = new Schema<RefreshToken>(
  {
    userId: { type: Schema.Types.ObjectId, required: true, index: true },
    tokenHash: { type: String, required: true },
    family: { type: String, required: true, index: true },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
    replacedByHash: { type: String, default: null },
    userAgent: { type: String, default: null, maxlength: 300 },
    ip: { type: String, default: null, maxlength: 64 },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);

refreshTokenSchema.index({ tokenHash: 1 }, { unique: true });
// MongoDB deletes documents automatically once they expire.
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

