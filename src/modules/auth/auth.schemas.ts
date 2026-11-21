import { z } from 'zod';

import { isCountryCode, toE164 } from '../../lib/phone.js';

export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_LENGTH = 128;

const email = z
  .string({ error: 'Email is required' })
  .trim()
  .toLowerCase()
  .max(254, 'Email is too long')
  .pipe(z.email({ error: 'Enter a valid email address' }));

const password = (label = 'Password') =>
  z
    .string({ error: `${label} is required` })
    .min(PASSWORD_MIN_LENGTH, `${label} must be at least ${PASSWORD_MIN_LENGTH} characters long`)
    .max(PASSWORD_MAX_LENGTH, `${label} must be at most ${PASSWORD_MAX_LENGTH} characters long`)
    .refine((v) => v.trim().length >= PASSWORD_MIN_LENGTH, {
      error: `${label} must contain at least ${PASSWORD_MIN_LENGTH} non-space characters`,
    });

const country = z
  .string({ error: 'Country is required' })
  .trim()
  .toUpperCase()
  .refine(isCountryCode, { error: 'Country must be an ISO 3166-1 alpha-2 code, e.g. "US"' });

const phoneInput = z.string({ error: 'Phone number is required' }).trim().min(4, 'Enter a valid phone number').max(30);

const fullName = z
  .string({ error: 'Full name is required' })
  .trim()
  .min(2, 'Full name must be at least 2 characters')
  .max(100, 'Full name must be at most 100 characters')
  .regex(/^[\p{L}\p{M}][\p{L}\p{M}' .-]*$/u, 'Full name may only contain letters, spaces, apostrophes, dots and hyphens')
  .transform((v) => v.replace(/\s+/g, ' '));

/** Registration. `phone` is normalized to E.164 using `country` for national numbers. */
export const registerSchema = z
  .strictObject({
    fullName,
    email,
    country,
    phone: phoneInput,
    password: password(),
    confirmPassword: z.string({ error: 'Please re-enter your password' }),
  })
  .superRefine((v, ctx) => {
    if (v.password !== v.confirmPassword) {
      ctx.addIssue({ code: 'custom', path: ['confirmPassword'], message: 'Passwords do not match' });
    }
    if (!toE164(v.phone, v.country)) {
      ctx.addIssue({ code: 'custom', path: ['phone'], message: `Enter a valid phone number for ${v.country}` });
    }
  })
  .transform(({ confirmPassword: _confirm, ...v }) => ({ ...v, phone: toE164(v.phone, v.country)! }));

/** Login with either email + password or phone (+ optional country) + password. */
export const loginSchema = z
  .strictObject({
    email: email.optional(),
    phone: phoneInput.optional(),
    country: country.optional(),
    password: z.string({ error: 'Password is required' }).min(1, 'Password is required').max(PASSWORD_MAX_LENGTH),
  })
  .superRefine((v, ctx) => {
    if (!v.email === !v.phone) {
      ctx.addIssue({ code: 'custom', path: ['email'], message: 'Provide either email or phone' });
      return;
    }
    if (v.phone && !toE164(v.phone, v.country)) {
      ctx.addIssue({
        code: 'custom',
        path: ['phone'],
        message: 'Enter a valid phone number in international format (e.g. +14155550123) or include country',
      });
    }
  })
  .transform((v) =>
    v.email
      ? { kind: 'email' as const, email: v.email, password: v.password }
      : { kind: 'phone' as const, phone: toE164(v.phone!, v.country)!, password: v.password },
  );

export const refreshSchema = z.strictObject({
  refreshToken: z.string({ error: 'refreshToken is required' }).min(20).max(200),
});

export const forgotPasswordSchema = z.strictObject({ email });

export const resetPasswordSchema = z
  .strictObject({
    email,
    code: z.string({ error: 'Code is required' }).trim().regex(/^\d{6}$/, 'Code must be 6 digits'),
    newPassword: password('New password'),
    confirmPassword: z.string({ error: 'Please re-enter your new password' }),
  })
  .refine((v) => v.newPassword === v.confirmPassword, { path: ['confirmPassword'], error: 'Passwords do not match' });

export const changePasswordSchema = z
  .strictObject({
    currentPassword: z.string({ error: 'Current password is required' }).min(1).max(PASSWORD_MAX_LENGTH),
    newPassword: password('New password'),
    confirmPassword: z.string({ error: 'Please re-enter your new password' }),
  })
  .refine((v) => v.newPassword === v.confirmPassword, { path: ['confirmPassword'], error: 'Passwords do not match' });

export type RegisterInput = z.output<typeof registerSchema>;
export type LoginInput = z.output<typeof loginSchema>;
export type ResetPasswordInput = z.output<typeof resetPasswordSchema>;
export type ChangePasswordInput = z.output<typeof changePasswordSchema>;
