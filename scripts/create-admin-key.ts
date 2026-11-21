/**
 * Generates an admin key (header X-Admin-Key) and the SHA-256 hash for ADMIN_API_KEY_HASHES.
 *   npm run admin:key
 */
import { createHash, randomBytes } from 'node:crypto';

const key = `adm_${randomBytes(32).toString('base64url')}`;
console.log(`Admin key:             ${key}   <- keep secret (password manager / secret store)`);
console.log(`ADMIN_API_KEY_HASHES:  ${createHash('sha256').update(key).digest('hex')}`);
