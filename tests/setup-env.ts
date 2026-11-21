// Deterministic configuration for tests (no real secrets, no real email).
Object.assign(process.env, {
  NODE_ENV: 'test',
  MONGODB_URI: 'mongodb://placeholder',
  JWT_ACCESS_SECRET: 'test-access-secret-test-access-secret-0123456789',
  RESET_CODE_SECRET: 'test-reset-secret-test-reset-secret-0123456789',
  MAIL_TRANSPORT: 'memory',
  RATE_LIMIT_ENABLED: 'false',
  RESET_CODE_RESEND_COOLDOWN_SECONDS: '0',
});
