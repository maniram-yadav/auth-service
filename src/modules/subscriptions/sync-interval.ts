import { z } from 'zod';

/**
 * How often the app must re-fetch the subscription expiry from the server.
 * Stored per tenant in the app_settings table under SYNC_INTERVAL_KEY.
 */
export const SYNC_INTERVAL_UNITS = ['minute', 'hour', 'day', 'month', 'year'] as const;
export type SyncIntervalUnit = (typeof SYNC_INTERVAL_UNITS)[number];

export const SYNC_INTERVAL_KEY = 'subscription.syncInterval';

export const UNIT_SECONDS: Record<SyncIntervalUnit, number> = {
  minute: 60,
  hour: 3_600,
  day: 86_400,
  month: 30 * 86_400,
  year: 365 * 86_400,
};

/** Bounds: at least 1 minute (protects the server), at most 1 year (keeps entitlements fresh). */
export const syncIntervalSchema = z
  .strictObject({
    value: z.number({ error: 'value must be a number' }).int('value must be a whole number').min(1).max(1000),
    unit: z.enum(SYNC_INTERVAL_UNITS, { error: `unit must be one of: ${SYNC_INTERVAL_UNITS.join(', ')}` }),
  })
  .refine((v) => v.value * UNIT_SECONDS[v.unit] <= UNIT_SECONDS.year, { error: 'Interval must not exceed 1 year' });

export type SyncInterval = z.output<typeof syncIntervalSchema>;

export const intervalSeconds = (i: SyncInterval): number => i.value * UNIT_SECONDS[i.unit];
