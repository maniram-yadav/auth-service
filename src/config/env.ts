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

    MONGODB_URI: z.string().min(1, 'MONGODB_URI is required'),

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

    /** Comma-separated browser origins allowed by CORS. Empty = no browser origins. */
    CORS_ORIGINS: csv,
    /** Comma-separated API keys. When set, every /api request must send `x-api-key`. */
    API_KEYS: csv,
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
