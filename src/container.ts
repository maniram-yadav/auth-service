import { readFileSync } from 'node:fs';

import type { Logger } from 'pino';

import type { Env } from './config/env.js';
import { AuthService } from './modules/auth/auth.service.js';
import { PasswordService } from './modules/auth/password.service.js';
import { TokenService } from './modules/auth/token.service.js';
import { ConsoleMailer, MemoryMailer } from './modules/mail/dev.mailers.js';
import { GmailMailer } from './modules/mail/gmail.mailer.js';
import type { Mailer } from './modules/mail/mailer.js';
import { createStorage } from './persistence/index.js';
import { planCatalog } from './modules/subscriptions/plans.js';
import { SubscriptionService } from './modules/subscriptions/subscription.service.js';
import { GooglePlayVerifier, type GoogleServiceAccount } from './modules/subscriptions/verifiers/google-play.verifier.js';
import { SandboxVerifier } from './modules/subscriptions/verifiers/sandbox.verifier.js';
import type { PurchaseVerifier } from './modules/subscriptions/verifiers/verifier.js';
import type { StorageProvider } from './persistence/types.js';
import { loadTenantConfigs, type TenantConfig } from './tenancy/tenant.js';
import { TenantRegistry } from './tenancy/tenant-registry.js';

export interface Container {
  env: Env;
  logger: Logger;
  mailer: Mailer;
  tokens: TokenService;
  auth: AuthService;
  tenants: TenantRegistry;
  storage: StorageProvider;
  subscriptions: SubscriptionService;
}

function loadServiceAccount(env: Env): GoogleServiceAccount {
  const raw = env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON ?? readFileSync(env.GOOGLE_PLAY_SERVICE_ACCOUNT_FILE!, 'utf8');
  const parsed = JSON.parse(raw) as Partial<GoogleServiceAccount>;
  if (!parsed.client_email || !parsed.private_key) throw new Error('Google Play service account JSON is missing client_email/private_key');
  return parsed as GoogleServiceAccount;
}

export function createVerifiers(env: Env, logger: Logger, fetchImpl?: typeof fetch): PurchaseVerifier[] {
  const verifiers: PurchaseVerifier[] = [];
  if (env.GOOGLE_PLAY_PACKAGE_NAME) {
    verifiers.push(
      new GooglePlayVerifier({
        packageName: env.GOOGLE_PLAY_PACKAGE_NAME,
        serviceAccount: loadServiceAccount(env),
        logger,
        ...(fetchImpl ? { fetch: fetchImpl } : {}),
      }),
    );
  }
  if (env.PAYMENTS_SANDBOX_ENABLED) verifiers.push(new SandboxVerifier());
  return verifiers;
}

export function createMailer(env: Env, logger: Logger): Mailer {
  switch (env.MAIL_TRANSPORT) {
    case 'gmail':
      return new GmailMailer({
        user: env.GMAIL_USER!,
        clientId: env.GOOGLE_CLIENT_ID!,
        clientSecret: env.GOOGLE_CLIENT_SECRET!,
        refreshToken: env.GOOGLE_REFRESH_TOKEN!,
        from: env.MAIL_FROM ?? `${env.APP_NAME} <${env.GMAIL_USER}>`,
      });
    case 'memory':
      return new MemoryMailer();
    case 'console':
      return new ConsoleMailer(logger);
  }
}

/** Composition root: wires concrete implementations together. */
export function createContainer(
  env: Env,
  logger: Logger,
  overrides: {
    mailer?: Mailer;
    tenantConfigs?: TenantConfig[];
    storage?: StorageProvider;
    verifiers?: PurchaseVerifier[];
  } = {},
): Container {
  const mailer = overrides.mailer ?? createMailer(env, logger);
  const storage = overrides.storage ?? createStorage(env, logger);
  const tenantConfigs = overrides.tenantConfigs ?? loadTenantConfigs(env);
  const tenants = new TenantRegistry(tenantConfigs, storage);
  const tokens = new TokenService(env);
  const auth = new AuthService({ config: env, passwords: new PasswordService(), tokens, mailer, logger });
  const subscriptions = new SubscriptionService({
    plans: planCatalog(env),
    verifiers: overrides.verifiers ?? createVerifiers(env, logger),
    defaultSyncInterval: { value: env.SUBSCRIPTION_SYNC_INTERVAL_VALUE, unit: env.SUBSCRIPTION_SYNC_INTERVAL_UNIT },
    accountSecret: env.RESET_CODE_SECRET,
    logger,
  });
  return { env, logger, mailer, tokens, auth, tenants, storage, subscriptions };
}
