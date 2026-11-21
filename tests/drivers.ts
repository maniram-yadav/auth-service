import mongoose from 'mongoose';
import pg from 'pg';
import { inject } from 'vitest';

import { createLogger } from '../src/lib/logger.js';
import { MongoStorageProvider } from '../src/persistence/mongo/mongo-storage.js';
import { physicalNames, type IsolationStrategy } from '../src/persistence/naming.js';
import { PgStorageProvider } from '../src/persistence/postgres/pg-storage.js';
import type { DbDriver, StorageProvider } from '../src/persistence/types.js';

export const DRIVERS: DbDriver[] = ['mongodb', 'postgres'];

const logger = createLogger({ NODE_ENV: 'test', LOG_LEVEL: 'silent' });

/**
 * Driver-specific plumbing for the shared test suites: creating a storage provider and
 * inspecting what was physically written (to prove isolation and hashing).
 */
export interface TestDriver {
  driver: DbDriver;
  /** Env overrides that select this driver in loadEnv(). */
  env: Record<string, string>;
  start(): Promise<void>;
  stop(): Promise<void>;
  storage(isolation: IsolationStrategy, prefix: string): StorageProvider;
  /** Empties every tenant table / collection (keeps structure). */
  clear(): Promise<void>;
  /** Collection or table names in the shared namespace. */
  listNames(): Promise<string[]>;
  count(name: string, namespace?: string | null): Promise<number>;
  /** Raw stored password hash of a user. */
  passwordHash(tenantId: string, email: string): Promise<string | null>;
  /** Raw stored reset code hash of a tenant (first row). */
  resetCodeHash(tenantId: string): Promise<string | null>;
  dropNamespace(namespace: string): Promise<void>;
}

export function testDriver(driver: DbDriver, suite: string): TestDriver {
  return driver === 'mongodb' ? mongoDriver(suite) : postgresDriver(suite);
}

function mongoDriver(suite: string): TestDriver {
  const providers: StorageProvider[] = [];
  return {
    driver: 'mongodb',
    env: { DB_DRIVER: 'mongodb', MONGODB_URI: 'mongodb://unused' },
    async start() {
      mongoose.set('sanitizeFilter', true);
      await mongoose.connect(inject('mongoUri'), { dbName: `${suite}_mongo` });
    },
    async stop() {
      await mongoose.connection.dropDatabase();
      await mongoose.disconnect();
    },
    storage(isolation, prefix) {
      const p = new MongoStorageProvider({ uri: 'unused', isolation, dbPrefix: prefix, logger });
      providers.push(p);
      return p;
    },
    async clear() {
      const collections = await mongoose.connection.db!.collections();
      await Promise.all(collections.map((c) => c.deleteMany({})));
    },
    async listNames() {
      return (await mongoose.connection.db!.listCollections().toArray()).map((c) => c.name);
    },
    async count(name, namespace) {
      const conn = namespace ? mongoose.connection.useDb(namespace) : mongoose.connection;
      return conn.collection(name).countDocuments();
    },
    async passwordHash(tenantId, email) {
      const doc = await mongoose.connection.db!.collection(physicalNames('collection', tenantId, '').users).findOne({ email });
      return (doc?.passwordHash as string | undefined) ?? null;
    },
    async resetCodeHash(tenantId) {
      const doc = await mongoose.connection.db!.collection(physicalNames('collection', tenantId, '').passwordResets).findOne({});
      return (doc?.codeHash as string | undefined) ?? null;
    },
    async dropNamespace(namespace) {
      await mongoose.connection.useDb(namespace).dropDatabase();
    },
  };
}

function postgresDriver(suite: string): TestDriver {
  const schema = `${suite}_pg`;
  const providers: PgStorageProvider[] = [];
  let admin: pg.Pool;
  const q = (s: string) => `"${s}"`;

  return {
    driver: 'postgres',
    env: { DB_DRIVER: 'postgres', DATABASE_URL: 'postgres://unused', PG_SCHEMA: schema },
    async start() {
      admin = new pg.Pool({ connectionString: inject('pgUrl'), max: 1 });
      await admin.query(`DROP SCHEMA IF EXISTS ${q(schema)} CASCADE`);
    },
    async stop() {
      await Promise.all(providers.map((p) => p.disconnect()));
      await admin.query(`DROP SCHEMA IF EXISTS ${q(schema)} CASCADE`);
      await admin.end();
    },
    storage(isolation, prefix) {
      const p = new PgStorageProvider({
        connectionString: inject('pgUrl'),
        isolation,
        schemaPrefix: prefix,
        sharedSchema: schema,
        poolMax: 1,
        ssl: false,
        purgeIntervalMinutes: 0,
        logger,
      });
      providers.push(p);
      return p;
    },
    async clear() {
      const { rows } = await admin.query<{ table_schema: string; table_name: string }>(
        `SELECT table_schema, table_name FROM information_schema.tables
         WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema')`,
      );
      if (rows.length) {
        await admin.query(`TRUNCATE ${rows.map((r) => `${q(r.table_schema)}.${q(r.table_name)}`).join(', ')} CASCADE`);
      }
    },
    async listNames() {
      const { rows } = await admin.query<{ table_name: string }>(
        'SELECT table_name FROM information_schema.tables WHERE table_schema = $1',
        [schema],
      );
      return rows.map((r) => r.table_name);
    },
    async count(name, namespace) {
      const { rows } = await admin.query<{ n: string }>(`SELECT count(*) AS n FROM ${q(namespace ?? schema)}.${q(name)}`);
      return Number(rows[0]!.n);
    },
    async passwordHash(tenantId, email) {
      const table = physicalNames('collection', tenantId, '').users;
      const { rows } = await admin.query<{ password_hash: string }>(
        `SELECT password_hash FROM ${q(schema)}.${q(table)} WHERE email = $1`,
        [email],
      );
      return rows[0]?.password_hash ?? null;
    },
    async resetCodeHash(tenantId) {
      const table = physicalNames('collection', tenantId, '').passwordResets;
      const { rows } = await admin.query<{ code_hash: string }>(`SELECT code_hash FROM ${q(schema)}.${q(table)} LIMIT 1`);
      return rows[0]?.code_hash ?? null;
    },
    async dropNamespace(namespace) {
      await admin.query(`DROP SCHEMA IF EXISTS ${q(namespace)} CASCADE`);
    },
  };
}
