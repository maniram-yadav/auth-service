/**
 * One-off migration from the single-tenant layout (users, refreshtokens, passwordresets)
 * to a tenant's collections (<tenant>_users, …). Dry-run by default.
 *
 *   npm run tenant:migrate -- <tenant_id>            # show what would happen
 *   npm run tenant:migrate -- <tenant_id> --apply    # rename the collections
 *
 * Requires MONGODB_URI. Uses renameCollection, so it is fast and keeps documents and indexes.
 * Existing access tokens stop working (they have no tenant claim); refresh tokens keep working.
 */
import mongoose from 'mongoose';

import { TENANT_ID_PATTERN } from '../src/tenancy/tenant.js';
import { physicalNames } from '../src/persistence/naming.js';

const [tenantId, flag] = process.argv.slice(2);
const apply = flag === '--apply';
const uri = process.env.MONGODB_URI;

if (!tenantId || !TENANT_ID_PATTERN.test(tenantId) || !uri) {
  console.error('Usage: MONGODB_URI=... npm run tenant:migrate -- <tenant_id> [--apply]');
  process.exit(1);
}

const LEGACY = { users: 'users', refreshTokens: 'refreshtokens', passwordResets: 'passwordresets' } as const;

async function main() {
  await mongoose.connect(uri!);
  const db = mongoose.connection.db!;
  const existing = new Set((await db.listCollections().toArray()).map((c) => c.name));
  const target = physicalNames('collection', tenantId!, '');

  for (const key of Object.keys(LEGACY) as (keyof typeof LEGACY)[]) {
    const from = LEGACY[key];
    const to = target[key];
    if (!existing.has(from)) {
      console.log(`skip    ${from} (not found)`);
      continue;
    }
    if (existing.has(to)) {
      console.error(`ABORT   ${to} already exists — refusing to overwrite`);
      process.exitCode = 1;
      continue;
    }
    const count = await db.collection(from).estimatedDocumentCount();
    if (apply) {
      await db.renameCollection(from, to);
      console.log(`renamed ${from} -> ${to} (${count} documents)`);
    } else {
      console.log(`would rename ${from} -> ${to} (${count} documents)`);
    }
  }
  if (!apply) console.log('\nDry run only. Re-run with --apply to perform the migration.');
  await mongoose.disconnect();
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
