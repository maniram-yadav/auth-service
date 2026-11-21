import { readFileSync } from 'node:fs';
import { z } from 'zod';

/**
 * Tenant id doubles as the collection / database name prefix, so it is restricted to a
 * safe character set: lower-case letter first, then lower-case letters, digits or "_".
 */
export const TENANT_ID_PATTERN = /^[a-z][a-z0-9_]{1,31}$/;

const sha256Hex = z.string().regex(/^[a-f0-9]{64}$/, 'apiKeyHashes entries must be SHA-256 hex digests');

export const TenantConfigSchema = z.strictObject({
  id: z.string().regex(TENANT_ID_PATTERN, 'id must match ^[a-z][a-z0-9_]{1,31}$'),
  name: z.string().min(1).max(100),
  /** SHA-256 of every API key that identifies this tenant (several allow key rotation). */
  apiKeyHashes: z.array(sha256Hex).min(1),
  /** Browser origins allowed for this tenant. Empty = only non-browser clients (mobile, servers). */
  allowedOrigins: z.array(z.url()).default([]),
  /** Disabled tenants are rejected with 403 but their data is kept. */
  enabled: z.boolean().default(true),
  mail: z
    .strictObject({
      /** Product name used in email subjects and bodies. */
      appName: z.string().min(1).max(60).optional(),
      /** "Name <address>" — must be the Gmail account or one of its verified aliases. */
      from: z.string().min(3).max(200).optional(),
    })
    .default({}),
});

export const TenantsFileSchema = z
  .strictObject({ tenants: z.array(TenantConfigSchema).min(1, 'At least one tenant is required') })
  .superRefine((file, ctx) => {
    const ids = new Set<string>();
    const keys = new Set<string>();
    file.tenants.forEach((t, i) => {
      if (ids.has(t.id)) ctx.addIssue({ code: 'custom', path: ['tenants', i, 'id'], message: `Duplicate tenant id "${t.id}"` });
      ids.add(t.id);
      t.apiKeyHashes.forEach((h, j) => {
        if (keys.has(h)) {
          ctx.addIssue({ code: 'custom', path: ['tenants', i, 'apiKeyHashes', j], message: 'API key is used by more than one tenant' });
        }
        keys.add(h);
      });
    });
  });

export type TenantConfig = z.output<typeof TenantConfigSchema>;

/** Loads tenant definitions from TENANTS_JSON (inline) or TENANTS_FILE (path). */
export function loadTenantConfigs(source: { TENANTS_JSON?: string | undefined; TENANTS_FILE?: string | undefined }): TenantConfig[] {
  let raw: string;
  let origin: string;
  if (source.TENANTS_JSON) {
    raw = source.TENANTS_JSON;
    origin = 'TENANTS_JSON';
  } else if (source.TENANTS_FILE) {
    raw = readFileSync(source.TENANTS_FILE, 'utf8');
    origin = source.TENANTS_FILE;
  } else {
    throw new Error('No tenants configured: set TENANTS_FILE (path to tenants.json) or TENANTS_JSON');
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    throw new Error(`${origin} is not valid JSON: ${(e as Error).message}`);
  }
  const parsed = TenantsFileSchema.safeParse(json);
  if (!parsed.success) {
    const details = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid tenant configuration in ${origin}:\n${details}`);
  }
  return parsed.data.tenants;
}
