import mongoose from 'mongoose';
import type { Logger } from 'pino';

// Reject query operators ($gt, $ne, …) smuggled inside filter values (NoSQL injection).
mongoose.set('sanitizeFilter', true);
mongoose.set('strictQuery', true);

export async function connectMongo(uri: string, logger: Logger): Promise<typeof mongoose> {
  mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
  mongoose.connection.on('reconnected', () => logger.info('MongoDB reconnected'));
  const connection = await mongoose.connect(uri, { serverSelectionTimeoutMS: 10_000, autoIndex: true });
  await mongoose.connection.syncIndexes();
  logger.info('MongoDB connected');
  return connection;
}

export const disconnectMongo = () => mongoose.disconnect();
