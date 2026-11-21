import mongoose, { Schema, type Model, type Types } from 'mongoose';

import {
  DuplicatePurchaseError,
  type AppSettingsRepository,
  type NewPurchase,
  type PaymentProvider,
  type PlanId,
  type PurchaseRecord,
  type PurchaseRepository,
  type RuleSyncRepository,
  type SubscriptionRecord,
  type SubscriptionRepository,
  type SubscriptionUpsert,
  type SyncedRule,
} from '../types.js';

/** MongoDB schemas + repositories for subscriptions, purchases, synced rules and tenant settings. */

const oid = (id: string) => new mongoose.Types.ObjectId(id);

// ---------------------------------------------------------------- subscriptions

interface SubscriptionDoc extends Omit<SubscriptionRecord, 'userId'> {
  userId: Types.ObjectId;
}

export const subscriptionSchema = new Schema<SubscriptionDoc>(
  {
    userId: { type: Schema.Types.ObjectId, required: true },
    planId: { type: String, required: true, enum: ['six_months', 'one_year', 'lifetime'] },
    provider: { type: String, required: true, enum: ['google_play', 'sandbox'] },
    productId: { type: String, required: true, maxlength: 200 },
    purchaseToken: { type: String, required: true, maxlength: 4096 },
    expiresAt: { type: Date, default: null },
    autoRenewing: { type: Boolean, required: true, default: false },
  },
  { timestamps: true, strict: 'throw' },
);
subscriptionSchema.index({ userId: 1 }, { unique: true });

const toSubscription = (d: SubscriptionDoc): SubscriptionRecord => ({
  userId: d.userId.toString(),
  planId: d.planId as PlanId,
  provider: d.provider as PaymentProvider,
  productId: d.productId,
  purchaseToken: d.purchaseToken,
  expiresAt: d.expiresAt ?? null,
  autoRenewing: d.autoRenewing,
  createdAt: d.createdAt,
  updatedAt: d.updatedAt,
});

export class MongoSubscriptionRepository implements SubscriptionRepository {
  constructor(private readonly model: Model<SubscriptionDoc>) {}

  async get(userId: string) {
    const doc = await this.model.findOne({ userId: oid(userId) }).lean<SubscriptionDoc>();
    return doc ? toSubscription(doc) : null;
  }

  async upsert(s: SubscriptionUpsert) {
    const { userId, ...fields } = s;
    const doc = await this.model
      .findOneAndUpdate(
        { userId: oid(userId) },
        { $set: fields, $setOnInsert: { userId: oid(userId) } },
        { upsert: true, returnDocument: 'after' },
      )
      .lean<SubscriptionDoc>();
    return toSubscription(doc!);
  }
}

// ---------------------------------------------------------------- purchases

interface PurchaseDoc extends Omit<PurchaseRecord, 'id' | 'userId'> {
  userId: Types.ObjectId;
}

export const purchaseSchema = new Schema<PurchaseDoc>(
  {
    userId: { type: Schema.Types.ObjectId, required: true, index: true },
    provider: { type: String, required: true },
    purchaseToken: { type: String, required: true, maxlength: 4096 },
    productId: { type: String, required: true },
    planId: { type: String, required: true },
    orderId: { type: String, default: null },
    purchasedAt: { type: Date, required: true },
    expiresAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);
purchaseSchema.index({ provider: 1, purchaseToken: 1 }, { unique: true });

type PurchaseLean = PurchaseDoc & { _id: Types.ObjectId };

const toPurchase = (d: PurchaseLean): PurchaseRecord => ({
  id: d._id.toString(),
  userId: d.userId.toString(),
  provider: d.provider as PaymentProvider,
  purchaseToken: d.purchaseToken,
  productId: d.productId,
  planId: d.planId as PlanId,
  orderId: d.orderId ?? null,
  purchasedAt: d.purchasedAt,
  expiresAt: d.expiresAt ?? null,
  createdAt: d.createdAt,
});

export class MongoPurchaseRepository implements PurchaseRepository {
  constructor(private readonly model: Model<PurchaseDoc>) {}

  async findByToken(provider: PaymentProvider, purchaseToken: string) {
    const doc = await this.model.findOne({ provider, purchaseToken }).lean<PurchaseLean>();
    return doc ? toPurchase(doc) : null;
  }

  async create(p: NewPurchase) {
    try {
      const doc = await this.model.create({ ...p, userId: oid(p.userId) });
      return toPurchase(doc.toObject() as PurchaseLean);
    } catch (e) {
      if ((e as { code?: number }).code === 11000) throw new DuplicatePurchaseError();
      throw e;
    }
  }
}

// ---------------------------------------------------------------- synced rules

interface RuleSetDoc {
  userId: Types.ObjectId;
  rules: SyncedRule[];
  updatedAt: Date;
}

const syncedRuleSchema = new Schema<SyncedRule>(
  {
    type: { type: String, required: true },
    countryIso: { type: String, required: true },
    anyCountry: { type: Boolean, required: true },
    pattern: { type: String, required: true },
    label: { type: String, default: null },
    enabled: { type: Boolean, required: true },
  },
  { _id: false, strict: 'throw' },
);

/** One document per user holding the whole rule set (replaced atomically). */
export const ruleSetSchema = new Schema<RuleSetDoc>(
  {
    userId: { type: Schema.Types.ObjectId, required: true },
    rules: { type: [syncedRuleSchema], default: [] },
  },
  { timestamps: { createdAt: false, updatedAt: true }, strict: 'throw' },
);
ruleSetSchema.index({ userId: 1 }, { unique: true });

const stripRule = (r: SyncedRule): SyncedRule => ({
  type: r.type,
  countryIso: r.countryIso,
  anyCountry: r.anyCountry,
  pattern: r.pattern,
  label: r.label ?? null,
  enabled: r.enabled,
});

export class MongoRuleSyncRepository implements RuleSyncRepository {
  constructor(private readonly model: Model<RuleSetDoc>) {}

  async list(userId: string) {
    const doc = await this.model.findOne({ userId: oid(userId) }).lean<RuleSetDoc>();
    return { rules: (doc?.rules ?? []).map(stripRule), updatedAt: doc?.updatedAt ?? null };
  }

  async replace(userId: string, rules: SyncedRule[]) {
    const doc = await this.model
      .findOneAndUpdate(
        { userId: oid(userId) },
        { $set: { rules: rules.map(stripRule) }, $setOnInsert: { userId: oid(userId) } },
        { upsert: true, returnDocument: 'after' },
      )
      .lean<RuleSetDoc>();
    return doc!.updatedAt;
  }
}

// ---------------------------------------------------------------- app settings

interface SettingDoc {
  key: string;
  value: unknown;
  updatedAt: Date;
}

export const settingSchema = new Schema<SettingDoc>(
  {
    key: { type: String, required: true, maxlength: 100 },
    value: { type: Schema.Types.Mixed, required: true },
  },
  { timestamps: { createdAt: false, updatedAt: true }, strict: 'throw' },
);
settingSchema.index({ key: 1 }, { unique: true });

export class MongoAppSettingsRepository implements AppSettingsRepository {
  constructor(private readonly model: Model<SettingDoc>) {}

  async get<T>(key: string) {
    const doc = await this.model.findOne({ key }).lean<SettingDoc>();
    return (doc?.value as T | undefined) ?? null;
  }

  async set(key: string, value: unknown) {
    await this.model.updateOne({ key }, { $set: { value } }, { upsert: true });
  }
}
