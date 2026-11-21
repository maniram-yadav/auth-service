import { PGlite } from '@electric-sql/pglite';
import { PGLiteSocketServer } from '@electric-sql/pglite-socket';
import { MongoMemoryServer } from 'mongodb-memory-server';
import type { TestProject } from 'vitest/node';

declare module 'vitest' {
  export interface ProvidedContext {
    mongoUri: string;
    pgUrl: string;
  }
}

let mongod: MongoMemoryServer | undefined;
let pglite: PGlite | undefined;
let pgServer: PGLiteSocketServer | undefined;

const PG_PORT = 55433;

/**
 * Starts one real MongoDB (mongodb-memory-server) and one real PostgreSQL
 * (PGlite over the Postgres wire protocol) for the whole run, so the `pg` driver
 * and the Mongo driver are both exercised end to end.
 */
export async function setup(project: TestProject) {
  mongod = await MongoMemoryServer.create({ instance: { launchTimeout: 120_000 } });
  pglite = await PGlite.create();
  pgServer = new PGLiteSocketServer({ db: pglite, port: PG_PORT, host: '127.0.0.1', maxConnections: 10 });
  await pgServer.start();

  project.provide('mongoUri', mongod.getUri());
  project.provide('pgUrl', `postgres://postgres:postgres@127.0.0.1:${PG_PORT}/postgres`);
}

export async function teardown() {
  await pgServer?.stop();
  await pglite?.close();
  await mongod?.stop();
}
