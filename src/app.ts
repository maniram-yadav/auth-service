import express, { type Express } from 'express';
import helmet from 'helmet';
import type { Logger } from 'pino';
import { pinoHttp } from 'pino-http';

import type { Env } from './config/env.js';
import { uuid } from './lib/crypto.js';
import { errorHandler, notFound } from './middleware/errors.js';
import { corsPolicy, createRateLimiters, noStore, requireJsonBody, resolveTenant } from './middleware/security.js';
import { createAuthRouter } from './modules/auth/auth.routes.js';
import type { AuthService } from './modules/auth/auth.service.js';
import type { TokenService } from './modules/auth/token.service.js';
import { createAdminRouter, createSubscriptionRouter } from './modules/subscriptions/subscription.routes.js';
import type { SubscriptionService } from './modules/subscriptions/subscription.service.js';
import { createRuleSyncRouter } from './modules/sync/rules-sync.js';
import type { StorageProvider } from './persistence/types.js';
import type { TenantRegistry } from './tenancy/tenant-registry.js';

export interface AppDeps {
  env: Env;
  logger: Logger;
  auth: AuthService;
  tokens: TokenService;
  tenants: TenantRegistry;
  storage: StorageProvider;
  subscriptions: SubscriptionService;
}

const REQUEST_ID = /^[\w-]{8,64}$/;

export function createApp({ env, logger, auth, tokens, tenants, storage, subscriptions }: AppDeps): Express {
  const app = express();
  const limits = createRateLimiters(env);

  app.disable('x-powered-by');
  app.set('trust proxy', env.TRUST_PROXY);
  app.set('query parser', 'simple');

  app.use(
    pinoHttp({
      logger,
      genReqId: (req, res) => {
        const incoming = req.headers['x-request-id'];
        const id = typeof incoming === 'string' && REQUEST_ID.test(incoming) ? incoming : uuid();
        res.setHeader('X-Request-Id', id);
        return id;
      },
      customLogLevel: (_req, res, err) => (err || res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info'),
    }),
  );
  app.use(helmet());
  app.use(corsPolicy([...env.CORS_ORIGINS, ...tenants.allowedOrigins()]));
  app.use(limits.global);

  // Health checks stay outside the tenant/API-key gate so orchestrators can probe them.
  app.get('/health/live', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.get('/health/ready', async (_req, res) => {
    const ready = await storage.isHealthy();
    res
      .status(ready ? 200 : 503)
      .json({ status: ready ? 'ok' : 'unavailable', database: ready ? 'up' : 'down', driver: storage.driver });
  });

  // Tenant first: unknown clients are rejected before their body is even parsed.
  // Small bodies everywhere; rule sync uploads up to 2000 rules, so it gets a larger (still bounded) limit.
  const smallJson = express.json({ limit: '10kb', strict: true });
  const syncJson = express.json({ limit: '512kb', strict: true });
  app.use('/api', noStore, resolveTenant(tenants), requireJsonBody, (req, res, next) =>
    (req.path.startsWith('/v1/sync/') ? syncJson : smallJson)(req, res, next),
  );
  app.use('/api/v1/auth', createAuthRouter(auth, tokens, limits));
  app.use('/api/v1/subscriptions', createSubscriptionRouter(subscriptions, tokens));
  app.use('/api/v1/sync', createRuleSyncRouter(tokens));
  app.use('/api/v1/admin', createAdminRouter(subscriptions, env.ADMIN_API_KEY_HASHES));

  app.use(notFound);
  app.use(errorHandler(logger, env.NODE_ENV === 'development'));
  return app;
}
