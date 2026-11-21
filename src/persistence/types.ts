/**
 * Storage-agnostic persistence ports. The auth use-cases depend only on these interfaces;
 * `mongo/` and `postgres/` provide the implementations, selected by DB_DRIVER.
 *
 * Every mutation that guards a security property (refresh-token rotation, reset-code attempts,
 * failed-login counting) is a single atomic operation in each implementation.
 */

export type DbDriver = 'mongodb' | 'postgres';

export interface UserRecord {
  /** Opaque id: ObjectId hex (MongoDB) or UUID (PostgreSQL). */
  id: string;
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

export interface NewUser {
  fullName: string;
  email: string;
  country: string;
  phone: string;
  passwordHash: string;
}

export interface NewRefreshToken {
  userId: string;
  tokenHash: string;
  family: string;
  expiresAt: Date;
  userAgent: string | null;
  ip: string | null;
}

export interface ResetAttempt {
  id: string;
  codeHash: string;
  /** Attempts used, including the one just counted. */
  attempts: number;
}

/** Thrown by `UserRepository.create` when a unique field already exists in the tenant. */
export class DuplicateKeyError extends Error {
  constructor(readonly field: 'email' | 'phone') {
    super(`Duplicate ${field}`);
    this.name = 'DuplicateKeyError';
  }
}

export interface UserRepository {
  /** Which of the given unique values are already registered. */
  findConflicts(email: string, phone: string): Promise<{ email: boolean; phone: boolean }>;
  /** @throws DuplicateKeyError */
  create(user: NewUser): Promise<UserRecord>;
  findById(id: string): Promise<UserRecord | null>;
  findByEmail(email: string): Promise<UserRecord | null>;
  findByPhone(phone: string): Promise<UserRecord | null>;
  getTokenVersion(id: string): Promise<number | null>;
  /** Atomically counts a failed login; locks the account when the limit is reached. Returns true if locked. */
  recordFailedLogin(id: string, maxAttempts: number, lockUntil: Date): Promise<boolean>;
  /** Resets the failure counter / lock, stamps lastLoginAt and optionally upgrades the hash. */
  recordSuccessfulLogin(id: string, upgradedHash?: string): Promise<void>;
  /** Stores a new hash, unlocks, and increments tokenVersion. Returns the new tokenVersion. */
  setPassword(id: string, passwordHash: string): Promise<number>;
  /** Increments tokenVersion (sign out everywhere). Returns false if the user doesn't exist. */
  bumpTokenVersion(id: string): Promise<boolean>;
}

export interface RefreshTokenRepository {
  create(token: NewRefreshToken): Promise<void>;
  /** Atomically marks an active (unrevoked, unexpired) token as used and returns its owner. */
  consumeActive(tokenHash: string, now: Date): Promise<{ userId: string; family: string } | null>;
  findByHash(tokenHash: string): Promise<{ family: string; revokedAt: Date | null } | null>;
  revokeFamily(family: string, now: Date): Promise<void>;
  revoke(tokenHash: string, now: Date): Promise<void>;
  revokeAllForUser(userId: string, now: Date): Promise<void>;
  linkReplacement(oldHash: string, newHash: string): Promise<void>;
}

export interface PasswordResetRepository {
  findCreatedAt(userId: string): Promise<Date | null>;
  /** Replaces any existing code for the user (one active code per user). */
  replace(userId: string, codeHash: string, expiresAt: Date): Promise<void>;
  /** Atomically counts an attempt on an unexpired code that still has attempts left. */
  consumeAttempt(userId: string, now: Date, maxAttempts: number): Promise<ResetAttempt | null>;
  delete(id: string): Promise<void>;
  deleteForUser(userId: string): Promise<void>;
}

// ------------------------------------------------------------------ subscriptions

export type PlanId = 'six_months' | 'one_year' | 'lifetime';
export type PaymentProvider = 'google_play' | 'sandbox';

/** The user's current entitlement (one row per user). */
export interface SubscriptionRecord {
  userId: string;
  planId: PlanId;
  provider: PaymentProvider;
  /** Store product id of the purchase that granted the entitlement. */
  productId: string;
  /** Latest purchase token (used to re-verify renewals with the store). */
  purchaseToken: string;
  /** null = lifetime (never expires). */
  expiresAt: Date | null;
  autoRenewing: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export type SubscriptionUpsert = Omit<SubscriptionRecord, 'createdAt' | 'updatedAt'>;

/** Immutable audit row per verified store purchase. (provider, purchaseToken) is unique. */
export interface PurchaseRecord {
  id: string;
  userId: string;
  provider: PaymentProvider;
  purchaseToken: string;
  productId: string;
  planId: PlanId;
  orderId: string | null;
  purchasedAt: Date;
  expiresAt: Date | null;
  createdAt: Date;
}

export type NewPurchase = Omit<PurchaseRecord, 'id' | 'createdAt'>;

/** Thrown when a purchase token is already recorded (replay / sharing protection). */
export class DuplicatePurchaseError extends Error {
  constructor() {
    super('Purchase token already used');
    this.name = 'DuplicatePurchaseError';
  }
}

export interface SubscriptionRepository {
  get(userId: string): Promise<SubscriptionRecord | null>;
  upsert(subscription: SubscriptionUpsert): Promise<SubscriptionRecord>;
}

export interface PurchaseRepository {
  findByToken(provider: PaymentProvider, purchaseToken: string): Promise<PurchaseRecord | null>;
  /** @throws DuplicatePurchaseError */
  create(purchase: NewPurchase): Promise<PurchaseRecord>;
}

// ------------------------------------------------------------------ device data sync

/** A call-blocking rule as synced from the app (the app recomputes match digits locally). */
export interface SyncedRule {
  type: 'EXACT' | 'PREFIX' | 'SUFFIX' | 'CONTAINS';
  countryIso: string;
  anyCountry: boolean;
  pattern: string;
  label: string | null;
  enabled: boolean;
}

export interface RuleSyncRepository {
  list(userId: string): Promise<{ rules: SyncedRule[]; updatedAt: Date | null }>;
  /** Atomically replaces the user's stored rule set. */
  replace(userId: string, rules: SyncedRule[]): Promise<Date>;
}

// ------------------------------------------------------------------ tenant settings

/** Small key/value table for tenant-wide settings (e.g. the subscription sync interval). */
export interface AppSettingsRepository {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: unknown): Promise<void>;
}

/** All repositories of one tenant. */
export interface TenantStore {
  users: UserRepository;
  refreshTokens: RefreshTokenRepository;
  passwordResets: PasswordResetRepository;
  subscriptions: SubscriptionRepository;
  purchases: PurchaseRepository;
  rules: RuleSyncRepository;
  settings: AppSettingsRepository;
}

/** A database backend. One instance per process. */
export interface StorageProvider {
  readonly driver: DbDriver;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isHealthy(): Promise<boolean>;
  /** Repositories bound to the tenant's own collections / tables (created on first use, cached). */
  forTenant(tenantId: string): Promise<TenantStore>;
  /** Removes expired tokens / codes (PostgreSQL; MongoDB uses TTL indexes). Returns rows removed. */
  purgeExpired(): Promise<number>;
}
