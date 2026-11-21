import { Schema, type Types } from 'mongoose';

/** Mongo document shapes. Bound to per-tenant collections by MongoStorageProvider. */

export interface UserDoc {
  fullName: string;
  email: string;
  country: string;
  phone: string;
  passwordHash: string;
  passwordChangedAt: Date;
  tokenVersion: number;
  failedLoginAttempts: number;
  lockUntil: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface RefreshTokenDoc {
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

export interface PasswordResetDoc {
  userId: Types.ObjectId;
  codeHash: string;
  attempts: number;
  expiresAt: Date;
  createdAt: Date;
}

export const userSchema = new Schema<UserDoc>(
  {
    fullName: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, trim: true, lowercase: true, maxlength: 254 },
    country: { type: String, required: true, uppercase: true, minlength: 2, maxlength: 2 },
    phone: { type: String, required: true, trim: true, maxlength: 20 },
    passwordHash: { type: String, required: true },
    passwordChangedAt: { type: Date, required: true, default: () => new Date() },
    tokenVersion: { type: Number, required: true, default: 0 },
    failedLoginAttempts: { type: Number, required: true, default: 0 },
    lockUntil: { type: Date, default: null },
    lastLoginAt: { type: Date, default: null },
  },
  { timestamps: true, strict: 'throw' },
);
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ phone: 1 }, { unique: true });

/** Opaque refresh tokens — only a SHA-256 hash is stored. Rotated on use; `family` enables reuse detection. */
export const refreshTokenSchema = new Schema<RefreshTokenDoc>(
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
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL: MongoDB deletes expired tokens

/** One active reset code per user; only an HMAC of the code is stored. */
export const passwordResetSchema = new Schema<PasswordResetDoc>(
  {
    userId: { type: Schema.Types.ObjectId, required: true },
    codeHash: { type: String, required: true },
    attempts: { type: Number, required: true, default: 0 },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);
passwordResetSchema.index({ userId: 1 }, { unique: true });
passwordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
