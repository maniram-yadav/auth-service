import { Schema, model, type HydratedDocument, type Model, type Types } from 'mongoose';

export interface User {
  fullName: string;
  /** Lower-cased, unique. */
  email: string;
  /** ISO 3166-1 alpha-2, e.g. "US". */
  country: string;
  /** E.164, unique, e.g. "+14155550123". */
  phone: string;
  /** Argon2id hash. Never selected unless explicitly requested. */
  passwordHash: string;
  passwordChangedAt: Date;
  /** Incremented to invalidate every issued access token (password reset, logout-all). */
  tokenVersion: number;
  failedLoginAttempts: number;
  lockUntil: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type UserDocument = HydratedDocument<User>;

/** Shape returned by the API — no secrets or security counters. */
export interface PublicUser {
  id: string;
  fullName: string;
  email: string;
  country: string;
  phone: string;
  createdAt: string;
  updatedAt: string;
}

const userSchema = new Schema<User>(
  {
    fullName: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, trim: true, lowercase: true, maxlength: 254 },
    country: { type: String, required: true, uppercase: true, minlength: 2, maxlength: 2 },
    phone: { type: String, required: true, trim: true, maxlength: 20 },
    passwordHash: { type: String, required: true, select: false },
    passwordChangedAt: { type: Date, required: true, default: () => new Date() },
    tokenVersion: { type: Number, required: true, default: 0 },
    failedLoginAttempts: { type: Number, required: true, default: 0 },
    lockUntil: { type: Date, default: null },
    lastLoginAt: { type: Date, default: null },
  },
  {
    timestamps: true,
    strict: 'throw',
    toJSON: {
      transform: (_doc, ret: Record<string, unknown>) => {
        delete ret.passwordHash;
        return ret;
      },
    },
  },
);

userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ phone: 1 }, { unique: true });

export const UserModel: Model<User> = model<User>('User', userSchema);

export function toPublicUser(user: Pick<User, 'fullName' | 'email' | 'country' | 'phone' | 'createdAt' | 'updatedAt'> & { _id: Types.ObjectId }): PublicUser {
  return {
    id: user._id.toString(),
    fullName: user.fullName,
    email: user.email,
    country: user.country,
    phone: user.phone,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  };
}
