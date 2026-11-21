import { Router, type Request } from 'express';

import type { TenantContext } from '../../tenancy/tenant-registry.js';

import { requireAuth, validateBody, type RateLimiters } from '../../middleware/security.js';
import {
  changePasswordSchema,
  forgotPasswordSchema,
  loginSchema,
  refreshSchema,
  registerSchema,
  resetPasswordSchema,
  type ChangePasswordInput,
  type LoginInput,
  type RegisterInput,
  type ResetPasswordInput,
} from './auth.schemas.js';
import type { AuthService } from './auth.service.js';
import type { ClientContext, TokenService } from './token.service.js';

const clientContext = (req: Request): ClientContext => ({
  userAgent: req.get('user-agent') ?? null,
  ip: req.ip ?? null,
});

/** resolveTenant runs before this router, so the tenant is always present. */
const tenantOf = (req: Request): TenantContext => req.tenant!;

const FORGOT_PASSWORD_MESSAGE =
  'If an account exists for this email, a reset code has been sent. It expires in a few minutes.';

/** HTTP layer only: validation + mapping to AuthService use-cases. */
export function createAuthRouter(auth: AuthService, tokens: TokenService, limits: RateLimiters): Router {
  const router = Router();
  const authenticated = requireAuth(tokens);

  router.post('/register', limits.register, validateBody(registerSchema), async (req, res) => {
    const result = await auth.register(tenantOf(req), req.body as RegisterInput, clientContext(req));
    res.status(201).json(result);
  });

  router.post('/login', limits.login, validateBody(loginSchema), async (req, res) => {
    res.json(await auth.login(tenantOf(req), req.body as LoginInput, clientContext(req)));
  });

  router.post('/refresh', limits.refresh, validateBody(refreshSchema), async (req, res) => {
    const tokens = await auth.refresh(tenantOf(req), (req.body as { refreshToken: string }).refreshToken, clientContext(req));
    res.json({ tokens });
  });

  router.post('/logout', validateBody(refreshSchema), async (req, res) => {
    await auth.logout(tenantOf(req), (req.body as { refreshToken: string }).refreshToken);
    res.status(204).end();
  });

  router.post('/logout-all', authenticated, async (req, res) => {
    await auth.logoutAll(tenantOf(req), req.auth!.userId);
    res.status(204).end();
  });

  router.get('/me', authenticated, async (req, res) => {
    res.json({ user: await auth.me(tenantOf(req), req.auth!.userId) });
  });

  router.post('/forgot-password', limits.forgotPassword, validateBody(forgotPasswordSchema), async (req, res) => {
    await auth.forgotPassword(tenantOf(req), (req.body as { email: string }).email);
    res.status(202).json({ message: FORGOT_PASSWORD_MESSAGE });
  });

  router.post('/reset-password', limits.resetPassword, validateBody(resetPasswordSchema), async (req, res) => {
    await auth.resetPassword(tenantOf(req), req.body as ResetPasswordInput);
    res.json({ message: 'Password has been reset. Please sign in with your new password.' });
  });

  router.post('/change-password', authenticated, validateBody(changePasswordSchema), async (req, res) => {
    const tokens = await auth.changePassword(tenantOf(req), req.auth!.userId, req.body as ChangePasswordInput, clientContext(req));
    res.json({ message: 'Password changed. Other sessions were signed out.', tokens });
  });

  return router;
}
