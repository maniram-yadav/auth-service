import cors from 'cors';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { ipKeyGenerator, rateLimit, type Options } from 'express-rate-limit';
import type { ZodType } from 'zod';

import type { Env } from '../config/env.js';
import { AppError } from '../lib/errors.js';
import type { TokenService } from '../modules/auth/token.service.js';
import type { TenantRegistry } from '../tenancy/tenant-registry.js';

/** Replaces req.body with the parsed (trimmed, normalized, unknown-keys-rejected) value. */
export const validateBody =
  (schema: ZodType): RequestHandler =>
  (req, _res, next) => {
    const result = schema.safeParse(req.body ?? {});
    if (!result.success) {
      const details = result.error.issues.map((issue) => ({
        field: issue.path.join('.') || 'body',
        message: issue.message,
      }));
      next(AppError.badRequest('Validation failed', details));
      return;
    }
    req.body = result.data;
    next();
  };

/** Verifies the Bearer access token and that it hasn't been revoked by a tokenVersion bump. */
export const requireAuth =
  (tokens: TokenService): RequestHandler =>
  async (req, _res, next) => {
    const header = req.get('authorization') ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) {
      throw AppError.unauthorized('Missing bearer token');
    }
    const tenant = req.tenant;
    if (!tenant) throw AppError.unauthorized('Unknown tenant');
    // The token must have been issued for this tenant, and the user must exist in its collection.
    const claims = tokens.verifyAccessToken(token, tenant.id);
    const tokenVersion = await tenant.store.users.getTokenVersion(claims.sub);
    if (tokenVersion === null || tokenVersion !== claims.tv) {
      throw AppError.unauthorized('Session is no longer valid', 'INVALID_TOKEN');
    }
    req.auth = { userId: claims.sub };
    next();
  };

export const TENANT_HEADER = 'x-tenant-id';
export const API_KEY_HEADER = 'x-api-key';

/**
 * Identifies the tenant (app / website) of every /api request from its API key.
 * - The key is the source of truth; an optional X-Tenant-Id must agree with it.
 * - Browser requests must come from one of the tenant's own allowed origins.
 * - Disabled tenants are rejected.
 */
export const resolveTenant =
  (registry: TenantRegistry): RequestHandler =>
  async (req, _res, next) => {
    const apiKey = req.get(API_KEY_HEADER);
    const config = apiKey ? registry.findByApiKey(apiKey) : undefined;
    if (!config) throw new AppError(401, 'UNAUTHORIZED', 'Invalid or missing API key');

    const claimed = req.get(TENANT_HEADER);
    if (claimed !== undefined && claimed !== config.id) {
      throw AppError.forbidden('X-Tenant-Id does not match the API key');
    }
    if (!config.enabled) throw AppError.forbidden('This application is disabled');

    const origin = req.get('origin');
    if (origin && !config.allowedOrigins.includes(origin)) {
      throw AppError.forbidden('Origin is not allowed for this application');
    }

    req.tenant = await registry.context(config);
    next();
  };

/** Only JSON request bodies are accepted (blocks form/CSRF-style and content-sniffing payloads). */
export const requireJsonBody: RequestHandler = (req, _res, next) => {
  const hasBody = Number(req.get('content-length') ?? 0) > 0 || req.get('transfer-encoding') !== undefined;
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && hasBody && !req.is('application/json')) {
    next(new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json'));
    return;
  }
  next();
};

/** Auth responses carry tokens/PII — never cache them. */
export const noStore: RequestHandler = (_req: Request, res: Response, next: NextFunction) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
};

export function corsPolicy(origins: readonly string[]): RequestHandler {
  return cors({
    origin: (origin, callback) => {
      // Native mobile apps and server-to-server calls send no Origin header.
      if (!origin || origins.includes(origin)) return callback(null, true);
      callback(null, false);
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Tenant-Id', 'X-Request-Id'],
    credentials: false,
    maxAge: 600,
  });
}

export interface RateLimiters {
  global: RequestHandler;
  register: RequestHandler;
  login: RequestHandler;
  refresh: RequestHandler;
  forgotPassword: RequestHandler;
  resetPassword: RequestHandler;
}

const clientIp = (req: Request) => ipKeyGenerator(req.ip ?? '0.0.0.0');

/**
 * Per-IP limits plus per-tenant + per-account limits on credential endpoints (stops distributed
 * guessing per user, and one tenant's traffic can't exhaust another tenant's budget).
 */
export function createRateLimiters(env: Pick<Env, 'RATE_LIMIT_ENABLED'>): RateLimiters {
  const make = (windowMinutes: number, limit: number, extra: Partial<Options> = {}): RequestHandler =>
    rateLimit({
      windowMs: windowMinutes * 60_000,
      limit,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      skip: () => !env.RATE_LIMIT_ENABLED,
      handler: (_req, _res, next) => next(new AppError(429, 'RATE_LIMITED', 'Too many requests, please try again later')),
      ...extra,
    });

  const identifier = (req: Request) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const id = typeof body.email === 'string' ? body.email : typeof body.phone === 'string' ? body.phone : '';
    return id.trim().toLowerCase().replace(/[^\w@.+]/g, '');
  };

  const perTenantIp = (req: Request) => `${req.tenant?.id ?? '-'}|${clientIp(req)}`;
  const perAccount = (req: Request) => `${perTenantIp(req)}|${identifier(req)}`;

  return {
    global: make(15, 300),
    register: make(60, 10, { keyGenerator: perTenantIp }),
    login: make(15, 20, { keyGenerator: perAccount }),
    refresh: make(15, 60, { keyGenerator: perTenantIp }),
    forgotPassword: make(60, 5, { keyGenerator: perAccount }),
    resetPassword: make(15, 10, { keyGenerator: perAccount }),
  };
}
