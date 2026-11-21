import { Schema, type Types } from 'mongoose';

/** One active reset code per user. The code itself is never stored — only an HMAC of it. */
export interface PasswordReset {
  userId: Types.ObjectId;
  codeHash: string;
  attempts: number;
  expiresAt: Date;
  createdAt: Date;
}

export const passwordResetSchema = new Schema<PasswordReset>(
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

