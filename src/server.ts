import { createApp } from './app.js';
import { loadEnv } from './config/env.js';
import { createContainer } from './container.js';
import { createLogger } from './lib/logger.js';

async function main() {
  const env = loadEnv();
  const logger = createLogger(env);
  const container = createContainer(env, logger);

  await container.storage.connect();
  // Create every tenant's collections and indexes up front (they are otherwise created lazily).
  await Promise.all(container.tenants.list().map((t) => container.tenants.context(t)));
  logger.info(
    { tenants: container.tenants.list().map((t) => t.id), driver: env.DB_DRIVER, isolation: env.TENANT_ISOLATION },
    'tenants ready',
  );
  container.mailer.verify().then(
    () => logger.info({ transport: env.MAIL_TRANSPORT }, 'mail transport ready'),
    (err: unknown) => logger.error({ err }, 'mail transport verification failed — reset emails will not be delivered'),
  );

  const app = createApp(container);
  const server = app.listen(env.PORT, () => logger.info({ port: env.PORT }, 'auth-service listening'));
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    server.close(async () => {
      await container.storage.disconnect();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', (err) => logger.error({ err }, 'unhandled rejection'));
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
