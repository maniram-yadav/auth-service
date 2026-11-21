import type { Logger } from 'pino';

import type { Env } from './config/env.js';
import { AuthService } from './modules/auth/auth.service.js';
import { PasswordService } from './modules/auth/password.service.js';
import { TokenService } from './modules/auth/token.service.js';
import { ConsoleMailer, MemoryMailer } from './modules/mail/dev.mailers.js';
import { GmailMailer } from './modules/mail/gmail.mailer.js';
import type { Mailer } from './modules/mail/mailer.js';
import { loadTenantConfigs, type TenantConfig } from './tenancy/tenant.js';
import { TenantModelFactory } from './tenancy/tenant-models.js';
import { TenantRegistry } from './tenancy/tenant-registry.js';

export interface Container {
  env: Env;
  logger: Logger;
  mailer: Mailer;
  tokens: TokenService;
  auth: AuthService;
  tenants: TenantRegistry;
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
  overrides: { mailer?: Mailer; tenantConfigs?: TenantConfig[] } = {},
): Container {
  const mailer = overrides.mailer ?? createMailer(env, logger);
  const tenantConfigs = overrides.tenantConfigs ?? loadTenantConfigs(env);
  const tenants = new TenantRegistry(tenantConfigs, new TenantModelFactory(env.TENANT_ISOLATION, env.TENANT_DB_PREFIX));
  const tokens = new TokenService(env);
  const auth = new AuthService({ config: env, passwords: new PasswordService(), tokens, mailer, logger });
  return { env, logger, mailer, tokens, auth, tenants };
}
