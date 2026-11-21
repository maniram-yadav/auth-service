import mongoose, { type Connection, type Model } from 'mongoose';
import type { Logger } from 'pino';

import { physicalNames, TenantCache, type IsolationStrategy } from '../naming.js';
import {
  DuplicateKeyError,
  type NewRefreshToken,
  type NewUser,
  type PasswordResetRepository,
  type RefreshTokenRepository,
  type ResetAttempt,
  type StorageProvider,
  type TenantStore,
  type UserRecord,
  type UserRepository,
} from '../types.js';
import {
  passwordResetSchema,
  refreshTokenSchema,
  userSchema,
  type PasswordResetDoc,
  type RefreshTokenDoc,
  type UserDoc,
} from './schemas.js';

// Reject query operators ($gt, $ne, …) smuggled inside filter values (NoSQL injection).
mongoose.set('sanitizeFilter', true);
mongoose.set('strictQuery', true);

/** Server-built operators are wrapped in trusted() so the global sanitizeFilter keeps them. */
const op = <T extends object>(value: T) => mongoose.trusted(value) as unknown as T;

const oid = (id: string) => new mongoose.Types.ObjectId(id);

type UserLean = UserDoc & { _id: mongoose.Types.ObjectId };

const toUser = (doc: UserLean): UserRecord => ({
  id: doc._id.toString(),
  fullName: doc.fullName,
  email: doc.email,
  country: doc.country,
  phone: doc.phone,
  passwordHash: doc.passwordHash,
  passwordChangedAt: doc.passwordChangedAt,
  tokenVersion: doc.tokenVersion,
  failedLoginAttempts: doc.failedLoginAttempts,
  lockUntil: doc.lockUntil ?? null,
  lastLoginAt: doc.lastLoginAt ?? null,
  createdAt: doc.createdAt,
  updatedAt: doc.updatedAt,
});

class MongoUserRepository implements UserRepository {
  constructor(private readonly users: Model<UserDoc>) {}

  async findConflicts(email: string, phone: string) {
    const existing = await this.users.find({ $or: [{ email }, { phone }] }, { email: 1, phone: 1 }).lean();
    return { email: existing.some((u) => u.email === email), phone: existing.some((u) => u.phone === phone) };
  }

  async create(user: NewUser): Promise<UserRecord> {
    try {
      const doc = await this.users.create(user);
      return toUser(doc.toObject() as UserLean);
    } catch (e) {
      const err = e as { code?: number; keyPattern?: Record<string, unknown> };
      if (err.code === 11000) throw new DuplicateKeyError(err.keyPattern && 'phone' in err.keyPattern ? 'phone' : 'email');
      throw e;
    }
  }

  async findById(id: string) {
    if (!mongoose.isValidObjectId(id)) return null;
    const doc = await this.users.findById(id).lean<UserLean>();
    return doc ? toUser(doc) : null;
  }

  async findByEmail(email: string) {
    const doc = await this.users.findOne({ email }).lean<UserLean>();
    return doc ? toUser(doc) : null;
  }

  async findByPhone(phone: string) {
    const doc = await this.users.findOne({ phone }).lean<UserLean>();
    return doc ? toUser(doc) : null;
  }

  async getTokenVersion(id: string) {
    if (!mongoose.isValidObjectId(id)) return null;
    const doc = await this.users.findById(id, { tokenVersion: 1 }).lean();
    return doc ? doc.tokenVersion : null;
  }

  async recordFailedLogin(id: string, maxAttempts: number, lockUntil: Date) {
    const updated = await this.users.findOneAndUpdate(
      { _id: oid(id) },
      { $inc: { failedLoginAttempts: 1 } },
      { returnDocument: 'after', projection: { failedLoginAttempts: 1 } },
    );
    if (!updated || updated.failedLoginAttempts < maxAttempts) return false;
    await this.users.updateOne({ _id: oid(id) }, { $set: { failedLoginAttempts: 0, lockUntil } });
    return true;
  }

  async recordSuccessfulLogin(id: string, upgradedHash?: string) {
    const set: Record<string, unknown> = { failedLoginAttempts: 0, lockUntil: null, lastLoginAt: new Date() };
    if (upgradedHash) set.passwordHash = upgradedHash;
    await this.users.updateOne({ _id: oid(id) }, { $set: set });
  }

  async setPassword(id: string, passwordHash: string) {
    const updated = await this.users.findOneAndUpdate(
      { _id: oid(id) },
      {
        $set: { passwordHash, passwordChangedAt: new Date(), failedLoginAttempts: 0, lockUntil: null },
        $inc: { tokenVersion: 1 },
      },
      { returnDocument: 'after', projection: { tokenVersion: 1 } },
    );
    return updated?.tokenVersion ?? 0;
  }

  async bumpTokenVersion(id: string) {
    if (!mongoose.isValidObjectId(id)) return false;
    const res = await this.users.updateOne({ _id: oid(id) }, { $inc: { tokenVersion: 1 } });
    return res.matchedCount > 0;
  }
}

class MongoRefreshTokenRepository implements RefreshTokenRepository {
  constructor(private readonly tokens: Model<RefreshTokenDoc>) {}

  async create(token: NewRefreshToken) {
    await this.tokens.create({ ...token, userId: oid(token.userId) });
  }

  async consumeActive(tokenHash: string, now: Date) {
    const record = await this.tokens.findOneAndUpdate(
      { tokenHash, revokedAt: null, expiresAt: op({ $gt: now }) },
      { $set: { revokedAt: now } },
      { returnDocument: 'before' },
    );
    return record ? { userId: record.userId.toString(), family: record.family } : null;
  }

  async findByHash(tokenHash: string) {
    const record = await this.tokens.findOne({ tokenHash }, { family: 1, revokedAt: 1 }).lean();
    return record ? { family: record.family, revokedAt: record.revokedAt ?? null } : null;
  }

  async revokeFamily(family: string, now: Date) {
    await this.tokens.updateMany({ family, revokedAt: null }, { $set: { revokedAt: now } });
  }

  async revoke(tokenHash: string, now: Date) {
    await this.tokens.updateOne({ tokenHash, revokedAt: null }, { $set: { revokedAt: now } });
  }

  async revokeAllForUser(userId: string, now: Date) {
    await this.tokens.updateMany({ userId: oid(userId), revokedAt: null }, { $set: { revokedAt: now } });
  }

  async linkReplacement(oldHash: string, newHash: string) {
    await this.tokens.updateOne({ tokenHash: oldHash }, { $set: { replacedByHash: newHash } });
  }
}

class MongoPasswordResetRepository implements PasswordResetRepository {
  constructor(private readonly resets: Model<PasswordResetDoc>) {}

  async findCreatedAt(userId: string) {
    const doc = await this.resets.findOne({ userId: oid(userId) }, { createdAt: 1 }).lean();
    return doc?.createdAt ?? null;
  }

  async replace(userId: string, codeHash: string, expiresAt: Date) {
    await this.resets.deleteMany({ userId: oid(userId) });
    await this.resets.create({ userId: oid(userId), codeHash, attempts: 0, expiresAt });
  }

  async consumeAttempt(userId: string, now: Date, maxAttempts: number): Promise<ResetAttempt | null> {
    const doc = await this.resets.findOneAndUpdate(
      { userId: oid(userId), expiresAt: op({ $gt: now }), attempts: op({ $lt: maxAttempts }) },
      { $inc: { attempts: 1 } },
      { returnDocument: 'after' },
    );
    return doc ? { id: doc._id.toString(), codeHash: doc.codeHash, attempts: doc.attempts } : null;
  }

  async delete(id: string) {
    await this.resets.deleteOne({ _id: oid(id) });
  }

  async deleteForUser(userId: string) {
    await this.resets.deleteMany({ userId: oid(userId) });
  }
}

export interface MongoStorageOptions {
  uri: string;
  isolation: IsolationStrategy;
  dbPrefix: string;
  logger: Logger;
  /** Use an existing connection (tests). Defaults to the global mongoose connection. */
  connection?: Connection;
}

/** MongoDB backend: collection per tenant or database per tenant. */
export class MongoStorageProvider implements StorageProvider {
  readonly driver = 'mongodb' as const;
  private readonly connection: Connection;
  private readonly cache = new TenantCache<TenantStore>((id) => this.build(id));

  constructor(private readonly options: MongoStorageOptions) {
    this.connection = options.connection ?? mongoose.connection;
  }

  async connect() {
    const { logger } = this.options;
    this.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
    this.connection.on('reconnected', () => logger.info('MongoDB reconnected'));
    if (this.connection.readyState !== mongoose.ConnectionStates.connected) {
      await mongoose.connect(this.options.uri, { serverSelectionTimeoutMS: 10_000, autoIndex: true });
    }
    logger.info('MongoDB connected');
  }

  async disconnect() {
    await mongoose.disconnect();
  }

  async isHealthy() {
    return this.connection.readyState === mongoose.ConnectionStates.connected;
  }

  forTenant(tenantId: string) {
    return this.cache.get(tenantId);
  }

  /** MongoDB TTL indexes remove expired documents automatically. */
  async purgeExpired() {
    return 0;
  }

  private async build(tenantId: string): Promise<TenantStore> {
    const names = physicalNames(this.options.isolation, tenantId, this.options.dbPrefix);
    const conn = names.namespace ? this.connection.useDb(names.namespace, { useCache: true }) : this.connection;
    // Model names must be unique per connection; prefix them on the shared connection.
    const modelName = (base: string) => (names.namespace ? base : `${tenantId}:${base}`);
    const bind = <T>(base: string, schema: mongoose.Schema<T>, collection: string): Model<T> =>
      (conn.models[modelName(base)] as Model<T> | undefined) ?? conn.model<T>(modelName(base), schema, collection);

    const users = bind('User', userSchema, names.users);
    const tokens = bind('RefreshToken', refreshTokenSchema, names.refreshTokens);
    const resets = bind('PasswordReset', passwordResetSchema, names.passwordResets);
    await Promise.all([users.init(), tokens.init(), resets.init()]); // unique + TTL indexes

    return {
      users: new MongoUserRepository(users),
      refreshTokens: new MongoRefreshTokenRepository(tokens),
      passwordResets: new MongoPasswordResetRepository(resets),
    };
  }
}
