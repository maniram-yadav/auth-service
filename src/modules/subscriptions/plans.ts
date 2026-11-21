import type { Env } from '../../config/env.js';
import type { PlanId } from '../../persistence/types.js';

export interface Plan {
  id: PlanId;
  title: string;
  /** List price in USD (the store shows the localized price at checkout). */
  priceUsd: number;
  /** Duration in months; null = lifetime. */
  durationMonths: number | null;
  /** Google Play product id (subscription id for timed plans, in-app product id for lifetime). */
  productId: string;
  /** Play product type: auto-renewing subscription or one-time (non-consumable) product. */
  storeType: 'subs' | 'in-app';
}

type PlanEnv = Pick<Env, 'PLAN_SIX_MONTHS_PRODUCT_ID' | 'PLAN_ONE_YEAR_PRODUCT_ID' | 'PLAN_LIFETIME_PRODUCT_ID'>;

/** The three plans offered in the app. Product ids are configurable to match the Play Console. */
export function planCatalog(env: PlanEnv): Plan[] {
  return [
    { id: 'six_months', title: '6 months', priceUsd: 10, durationMonths: 6, productId: env.PLAN_SIX_MONTHS_PRODUCT_ID, storeType: 'subs' },
    { id: 'one_year', title: '1 year', priceUsd: 15, durationMonths: 12, productId: env.PLAN_ONE_YEAR_PRODUCT_ID, storeType: 'subs' },
    { id: 'lifetime', title: 'Lifetime', priceUsd: 20, durationMonths: null, productId: env.PLAN_LIFETIME_PRODUCT_ID, storeType: 'in-app' },
  ];
}

/** Adds calendar months (UTC), clamping to the last day of shorter months. */
export function addMonths(from: Date, months: number): Date {
  const d = new Date(from.getTime());
  const day = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() + months);
  const lastDay = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, lastDay));
  return d;
}
