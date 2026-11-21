import { MongoMemoryServer } from 'mongodb-memory-server';
import type { TestProject } from 'vitest/node';

declare module 'vitest' {
  export interface ProvidedContext {
    mongoUri: string;
  }
}

let mongod: MongoMemoryServer | undefined;

/** Starts one real (in-memory) MongoDB for the whole test run. */
export async function setup(project: TestProject) {
  mongod = await MongoMemoryServer.create({ instance: { launchTimeout: 120_000 } });
  project.provide('mongoUri', mongod.getUri());
}

export async function teardown() {
  await mongod?.stop();
}
