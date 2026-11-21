import { Router, type Request } from 'express';
import { z } from 'zod';

import { requireAuth, validateBody } from '../../middleware/security.js';
import type { SyncedRule } from '../../persistence/types.js';
import type { TenantContext } from '../../tenancy/tenant-registry.js';
import type { TokenService } from '../auth/token.service.js';

export const MAX_SYNCED_RULES = 2000;

const ruleSchema = z.strictObject({
  type: z.enum(['EXACT', 'PREFIX', 'SUFFIX', 'CONTAINS']),
  countryIso: z.string().trim().toUpperCase().regex(/^[A-Z]{2}$/, 'countryIso must be an ISO 3166-1 alpha-2 code'),
  anyCountry: z.boolean(),
  pattern: z.string().trim().regex(/^[\d\s()+.-]{1,30}$/, 'pattern may only contain digits and phone punctuation'),
  label: z.string().trim().max(60).nullable().default(null),
  enabled: z.boolean().default(true),
});

const syncSchema = z.strictObject({
  /**
   * merge:   union of server and device rules (device wins on conflicts) — used right after sign-up/login
   *          so a phone's local rules are added to the account and account rules are restored to the phone.
   * replace: the device's list becomes the account's list — used after edits on the phone.
   */
  mode: z.enum(['merge', 'replace']),
  rules: z.array(ruleSchema).max(MAX_SYNCED_RULES, `At most ${MAX_SYNCED_RULES} rules`),
});

/** Identity of a rule regardless of formatting: same type, scope and digits = same rule. */
export const ruleKey = (r: SyncedRule) => `${r.type}|${r.anyCountry ? '*' : r.countryIso}|${r.pattern.replace(/\D/g, '')}`;

export function mergeRules(server: SyncedRule[], device: SyncedRule[]): SyncedRule[] {
  const merged = new Map(server.map((r) => [ruleKey(r), r]));
  device.forEach((r) => merged.set(ruleKey(r), r));
  return [...merged.values()].slice(0, MAX_SYNCED_RULES);
}

/** Dedupe within one upload (keeps the last occurrence). */
const dedupe = (rules: SyncedRule[]) => [...new Map(rules.map((r) => [ruleKey(r), r])).values()];

export function createRuleSyncRouter(tokens: TokenService): Router {
  const router = Router();
  const authenticated = requireAuth(tokens);
  const tenantOf = (req: Request): TenantContext => req.tenant!;

  router.get('/rules', authenticated, async (req, res) => {
    const { rules, updatedAt } = await tenantOf(req).store.rules.list(req.auth!.userId);
    res.json({ rules, updatedAt: updatedAt?.toISOString() ?? null });
  });

  router.post('/rules', authenticated, validateBody(syncSchema), async (req, res) => {
    const { mode, rules } = req.body as z.output<typeof syncSchema>;
    const { store } = tenantOf(req);
    const userId = req.auth!.userId;
    const incoming = dedupe(rules);
    const next = mode === 'merge' ? mergeRules((await store.rules.list(userId)).rules, incoming) : incoming;
    const updatedAt = await store.rules.replace(userId, next);
    res.json({ rules: next, updatedAt: updatedAt.toISOString() });
  });

  return router;
}
