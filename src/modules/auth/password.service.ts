import argon2 from 'argon2';

/**
 * Password hashing with Argon2id (OWASP recommended). Passwords are hashed one-way, with a
 * per-password random salt embedded in the hash. They are never encrypted reversibly or stored.
 */
export class PasswordService {
  private readonly options = {
    type: argon2.argon2id,
    memoryCost: 19_456, // 19 MiB — OWASP minimum recommendation
    timeCost: 2,
    parallelism: 1,
  } as const;

  /** Pre-computed hash used to keep timing identical when a user does not exist. */
  private dummyHash: Promise<string> | null = null;

  hash(password: string): Promise<string> {
    return argon2.hash(password, this.options);
  }

  async verify(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  /** True when the hash was created with weaker parameters and should be upgraded. */
  needsRehash(hash: string): boolean {
    return argon2.needsRehash(hash, this.options);
  }

  /** Burns the same CPU time as a real verification (prevents user enumeration via timing). */
  async verifyDummy(password: string): Promise<void> {
    this.dummyHash ??= this.hash('dummy-password-for-timing');
    await this.verify(await this.dummyHash, password);
  }
}
