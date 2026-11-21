import mongoose from 'mongoose';
import supertest from 'supertest';
import { inject } from 'vitest';

import { createApp } from '../src/app.js';
import { loadEnv } from '../src/config/env.js';
import { createContainer } from '../src/container.js';
import { createLogger } from '../src/lib/logger.js';
import { MemoryMailer } from '../src/modules/mail/dev.mailers.js';

export async function connectTestDb(name: string) {
  mongoose.set('sanitizeFilter', true);
  await mongoose.connect(inject('mongoUri'), { dbName: name });
  await mongoose.connection.syncIndexes();
}

export async function clearDb() {
  const collections = await mongoose.connection.db!.collections();
  await Promise.all(collections.map((c) => c.deleteMany({})));
}

export async function disconnectTestDb() {
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
}

/** Builds the real Express app with an in-memory mailer. */
export function buildApp(envOverrides: Record<string, string> = {}) {
  const env = loadEnv({ ...process.env, ...envOverrides });
  const logger = createLogger(env);
  const mailer = new MemoryMailer();
  const container = createContainer(env, logger, { mailer });
  const app = createApp(container);
  return { app, api: supertest(app), mailer, env };
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
