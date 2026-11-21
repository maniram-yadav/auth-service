import type { UserRecord } from '../../persistence/types.js';

/** Shape returned by the API — no secrets or security counters. */
export interface PublicUser {
  id: string;
  /** Tenant (app / website) the account belongs to. */
  tenant: string;
  fullName: string;
  email: string;
  country: string;
  phone: string;
  createdAt: string;
  updatedAt: string;
}

export function toPublicUser(tenant: string, user: UserRecord): PublicUser {
  return {
    id: user.id,
    tenant,
    fullName: user.fullName,
    email: user.email,
    country: user.country,
    phone: user.phone,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  };
}
