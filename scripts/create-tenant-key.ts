/**
 * Generates an API key for a tenant and the SHA-256 hash to put in tenants.json.
 *
 *   npm run tenant:key -- <tenant_id>
 *
 * Give the key to the client app (it sends it as X-API-Key). Store only the hash in config.
 */
import { createHash, randomBytes } from 'node:crypto';

import { TENANT_ID_PATTERN } from '../src/tenancy/tenant.js';

const tenantId = process.argv[2];
if (!tenantId || !TENANT_ID_PATTERN.test(tenantId)) {
  console.error('Usage: npm run tenant:key -- <tenant_id>   (id must match ^[a-z][a-z0-9_]{1,31}$)');
  process.exit(1);
}

const key = `tk_${tenantId}_${randomBytes(24).toString('base64url')}`;
const hash = createHash('sha256').update(key).digest('hex');

console.log(`Tenant:        ${tenantId}`);
console.log(`API key:       ${key}        <- give to the client, never commit`);
console.log(`apiKeyHashes:  ${hash}   <- add to tenants.json`);
