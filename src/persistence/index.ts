import type { Logger } from 'pino';

import type { Env } from '../config/env.js';
import { MongoStorageProvider } from './mongo/mongo-storage.js';
import { PgStorageProvider } from './postgres/pg-storage.js';
import type { StorageProvider } from './types.js';

export type { StorageProvider, TenantStore } from './types.js';

/** Selects the database backend from DB_DRIVER. */
export function createStorage(env: Env, logger: Logger): StorageProvider {
  switch (env.DB_DRIVER) {
    case 'mongodb':
      return new MongoStorageProvider({
        uri: env.MONGODB_URI!,
        isolation: env.TENANT_ISOLATION,
        dbPrefix: env.TENANT_DB_PREFIX,
        logger,
      });
    case 'postgres':
      return new PgStorageProvider({
        connectionString: env.DATABASE_URL!,
        isolation: env.TENANT_ISOLATION,
        schemaPrefix: env.TENANT_DB_PREFIX,
        sharedSchema: env.PG_SCHEMA,
        poolMax: env.PG_POOL_MAX,
        ssl: env.PG_SSL,
        purgeIntervalMinutes: env.PG_PURGE_INTERVAL_MINUTES,
        logger,
      });
  }
}
