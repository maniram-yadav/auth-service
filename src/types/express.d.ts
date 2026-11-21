import type { TenantContext } from '../tenancy/tenant-registry.js';

declare global {
  namespace Express {
    interface Request {
      /** Set by `requireAuth` once the access token has been verified. */
      auth?: { userId: string };
      /** Set by `resolveTenant` from the API key — every /api request has one. */
      tenant?: TenantContext;
    }
  }
}

export {};
