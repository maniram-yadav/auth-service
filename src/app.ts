import express, { type Express } from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import type { Logger } from 'pino';
import { pinoHttp } from 'pino-http';

import type { Env } from './config/env.js';
import { uuid } from './lib/crypto.js';
import { errorHandler, notFound } from './middleware/errors.js';
import { corsPolicy, createRateLimiters, noStore, requireJsonBody, resolveTenant } from './middleware/security.js';
import { createAuthRouter } from './modules/auth/auth.routes.js';
import type { AuthService } from './modules/auth/auth.service.js';
import type { TokenService } from './modules/auth/token.service.js';
import type { TenantRegistry } from './tenancy/tenant-registry.js';

export interface AppDeps {
  env: Env;
  logger: Logger;
  auth: AuthService;
  tokens: TokenService;
  tenants: TenantRegistry;
}

const REQUEST_ID = /^[\w-]{8,64}$/;

export function createApp({ env, logger, auth, tokens, tenants }: AppDeps): Express {
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
  app.get('/health/ready', (_req, res) => {
    const ready = mongoose.connection.readyState === mongoose.ConnectionStates.connected;
    res.status(ready ? 200 : 503).json({ status: ready ? 'ok' : 'unavailable', database: ready ? 'up' : 'down' });
  });

  // Tenant first: unknown clients are rejected before their body is even parsed.
  app.use('/api', noStore, resolveTenant(tenants), requireJsonBody, express.json({ limit: '10kb', strict: true }));
  app.use('/api/v1/auth', createAuthRouter(auth, tokens, limits));

  app.use(notFound);
  app.use(errorHandler(logger, env.NODE_ENV === 'development'));
  return app;
}
