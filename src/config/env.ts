import { z } from 'zod';

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const csv = z
  .string()
  .default('')
  .transform((v) =>
    v
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

    /** Storage backend. Both support the same features and tenant isolation strategies. */
    DB_DRIVER: z.enum(['mongodb', 'postgres']).default('mongodb'),
    /** Required when DB_DRIVER=mongodb, e.g. mongodb://localhost:27017/auth_service */
    MONGODB_URI: z.string().optional(),
    /** Required when DB_DRIVER=postgres, e.g. postgres://user:pass@localhost:5432/auth_service */
    DATABASE_URL: z.string().optional(),
    /** Schema holding the tenant-prefixed tables (TENANT_ISOLATION=collection). */
    PG_SCHEMA: z.string().regex(/^[a-z_][a-z0-9_]{0,30}$/, 'PG_SCHEMA must be a lower-case identifier').default('public'),
    PG_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),
    /** Require TLS with certificate verification (managed databases). */
    PG_SSL: bool.default(false),
    /** How often expired refresh tokens / reset codes are deleted (0 = never). */
    PG_PURGE_INTERVAL_MINUTES: z.coerce.number().int().min(0).max(1440).default(60),

    /** HS256 signing secret for access tokens. Generate with: openssl rand -base64 48 */
    JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
    JWT_ISSUER: z.string().default('auth-service'),
    JWT_AUDIENCE: z.string().default('call-blocker-app'),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),

    /** Secret used to HMAC password-reset codes before they are stored. */
    RESET_CODE_SECRET: z.string().min(32, 'RESET_CODE_SECRET must be at least 32 characters'),
    RESET_CODE_TTL_MINUTES: z.coerce.number().int().min(5).max(60).default(15),
    RESET_CODE_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(5),
    RESET_CODE_RESEND_COOLDOWN_SECONDS: z.coerce.number().int().min(0).max(3600).default(60),

    LOGIN_MAX_FAILED_ATTEMPTS: z.coerce.number().int().min(3).max(20).default(5),
    LOGIN_LOCK_MINUTES: z.coerce.number().int().min(1).max(1440).default(15),

    /** Extra browser origins allowed by CORS (tenant allowedOrigins are added automatically). */
    CORS_ORIGINS: csv,

    /** Path to tenants.json (see tenants.example.json). Ignored when TENANTS_JSON is set. */
    TENANTS_FILE: z.string().optional(),
    /** Inline tenants JSON — handy for containers / secret managers. */
    TENANTS_JSON: z.string().optional(),
    /**
     * "collection": <tenant>_users etc. in a shared database (MongoDB) / schema (PostgreSQL).
     * "database":   one database (MongoDB) / schema (PostgreSQL) per tenant.
     */
    TENANT_ISOLATION: z.enum(['collection', 'database']).default('collection'),
    /** Database (MongoDB) / schema (PostgreSQL) prefix for TENANT_ISOLATION=database, e.g. "auth_" → auth_web_shop. */
    TENANT_DB_PREFIX: z.string().regex(/^[a-z0-9_]{0,20}$/).default('auth_'),
    /** Express "trust proxy" setting: number of hops in front of the service (0 = none). */
    TRUST_PROXY: z.coerce.number().int().min(0).max(10).default(0),
    RATE_LIMIT_ENABLED: bool.default(true),

    MAIL_TRANSPORT: z.enum(['gmail', 'console', 'memory']).default('console'),
    MAIL_FROM: z.string().optional(),
    APP_NAME: z.string().default('Call Blocker'),
    GMAIL_USER: z.email().optional(),
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GOOGLE_REFRESH_TOKEN: z.string().optional(),
  })
  .superRefine((env, ctx) => {
    if (env.DB_DRIVER === 'mongodb' && !env.MONGODB_URI) {
      ctx.addIssue({ code: 'custom', path: ['MONGODB_URI'], message: 'MONGODB_URI is required when DB_DRIVER=mongodb' });
    }
    if (env.DB_DRIVER === 'postgres' && !env.DATABASE_URL) {
      ctx.addIssue({ code: 'custom', path: ['DATABASE_URL'], message: 'DATABASE_URL is required when DB_DRIVER=postgres' });
    }
    if (!env.TENANTS_FILE && !env.TENANTS_JSON) {
      ctx.addIssue({ code: 'custom', path: ['TENANTS_FILE'], message: 'Set TENANTS_FILE or TENANTS_JSON' });
    }
    if (env.MAIL_TRANSPORT === 'gmail') {
      for (const key of ['GMAIL_USER', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REFRESH_TOKEN'] as const) {
        if (!env[key]) ctx.addIssue({ code: 'custom', path: [key], message: `${key} is required when MAIL_TRANSPORT=gmail` });
      }
    }
    if (env.NODE_ENV === 'production') {
      if (env.MAIL_TRANSPORT !== 'gmail') {
        ctx.addIssue({ code: 'custom', path: ['MAIL_TRANSPORT'], message: 'Production must use MAIL_TRANSPORT=gmail' });
      }
      if (env.JWT_ACCESS_SECRET === env.RESET_CODE_SECRET) {
        ctx.addIssue({ code: 'custom', path: ['RESET_CODE_SECRET'], message: 'Use different secrets for JWT and reset codes' });
      }
    }
  });

export type Env = z.infer<typeof EnvSchema>;

/** Parses and validates configuration; fails fast with a readable message. */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = EnvSchema.safeParse(source);
  if (!result.success) {
    const details = result.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${details}`);
  }
  return result.data;
}
