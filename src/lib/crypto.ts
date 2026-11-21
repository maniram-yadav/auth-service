import { createHash, createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';

/** URL-safe random token with [bytes] bytes of entropy. */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString('base64url');

export const uuid = (): string => randomUUID();

export const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

export const hmacSha256 = (value: string, secret: string): string =>
  createHmac('sha256', secret).update(value).digest('hex');

/** Uniformly random numeric code, e.g. "042917" (leading zeros kept). */
export const numericCode = (digits = 6): string =>
  Array.from({ length: digits }, () => randomInt(0, 10)).join('');

/** Constant-time string comparison (hashes first so lengths never leak). */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}
