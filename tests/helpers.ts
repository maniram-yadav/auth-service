import type { Express } from 'express';
import supertest from 'supertest';

import { createApp } from '../src/app.js';
import { loadEnv } from '../src/config/env.js';
import { createContainer } from '../src/container.js';
import { createLogger } from '../src/lib/logger.js';
import { MemoryMailer } from '../src/modules/mail/dev.mailers.js';
import type { TestDriver } from './drivers.js';
import { TEST_KEYS } from './setup-env.js';

/** A supertest client that sends a tenant's API key with every request. */
export function tenantClient(app: Express, apiKey: string | null) {
  const withKey = (test: supertest.Test) => (apiKey ? test.set('X-API-Key', apiKey) : test);
  const agent = supertest(app);
  return {
    get: (path: string) => withKey(agent.get(path)),
    post: (path: string) => withKey(agent.post(path)),
  };
}

/** Builds the real Express app on the given database driver with an in-memory mailer. */
export function buildApp(db: TestDriver, envOverrides: Record<string, string> = {}) {
  const env = loadEnv({ ...process.env, ...db.env, ...envOverrides });
  const logger = createLogger(env);
  const mailer = new MemoryMailer();
  const storage = db.storage(env.TENANT_ISOLATION, env.TENANT_DB_PREFIX);
  const container = createContainer(env, logger, { mailer, storage });
  const app = createApp(container);
  return {
    app,
    api: tenantClient(app, TEST_KEYS.mobile),
    web: tenantClient(app, TEST_KEYS.web),
    client: (key: string | null) => tenantClient(app, key),
    raw: supertest(app),
    mailer,
    env,
    container,
  };
}

export const validUser = {
  fullName: 'Jane Doe',
  email: 'Jane.Doe@Example.com',
  country: 'US',
  phone: '(415) 555-0123',
  password: 'correct horse',
  confirmPassword: 'correct horse',
};

/** Pulls the 6-digit code out of the last reset email sent to [to]. */
export function resetCodeFrom(mailer: MemoryMailer, to: string): string {
  const message = mailer.lastTo(to);
  const match = message?.text.match(/reset code is: (\d{6})/);
  if (!match?.[1]) throw new Error(`No reset code email for ${to}`);
  return match[1];
}
