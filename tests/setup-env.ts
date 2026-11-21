import { createHash } from 'node:crypto';

export const TEST_KEYS = {
  mobile: 'test-key-mobile-app-0123456789abcdef',
  web: 'test-key-web-portal-0123456789abcdef',
  disabled: 'test-key-disabled-0123456789abcdef',
};
export const WEB_ORIGIN = 'https://portal.example.com';

const hash = (key: string) => createHash('sha256').update(key).digest('hex');

// Deterministic configuration for tests (no real secrets, no real email).
Object.assign(process.env, {
  NODE_ENV: 'test',
  MONGODB_URI: 'mongodb://placeholder',
  JWT_ACCESS_SECRET: 'test-access-secret-test-access-secret-0123456789',
  RESET_CODE_SECRET: 'test-reset-secret-test-reset-secret-0123456789',
  MAIL_TRANSPORT: 'memory',
  RATE_LIMIT_ENABLED: 'false',
  RESET_CODE_RESEND_COOLDOWN_SECONDS: '0',
  TENANTS_JSON: JSON.stringify({
    tenants: [
      { id: 'mobile_app', name: 'Call Blocker Android', apiKeyHashes: [hash(TEST_KEYS.mobile)], mail: { appName: 'Call Blocker' } },
      {
        id: 'web_portal',
        name: 'Customer Website',
        apiKeyHashes: [hash(TEST_KEYS.web)],
        allowedOrigins: [WEB_ORIGIN],
        mail: { appName: 'Customer Portal', from: 'Customer Portal <portal@example.com>' },
      },
      { id: 'retired_app', name: 'Retired', apiKeyHashes: [hash(TEST_KEYS.disabled)], enabled: false },
    ],
  }),
});
