import type { MailMessage } from './mailer.js';

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function layout(appName: string, bodyHtml: string): string {
  return `<!doctype html><html><body style="margin:0;background:#f4f6fa;font-family:Arial,Helvetica,sans-serif;color:#101828">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" style="max-width:480px;background:#ffffff;border-radius:12px;padding:32px">
<tr><td><h1 style="margin:0 0 16px;font-size:20px">${escapeHtml(appName)}</h1>${bodyHtml}</td></tr>
</table></td></tr></table></body></html>`;
}

export function passwordResetCodeEmail(params: {
  to: string;
  name: string;
  code: string;
  ttlMinutes: number;
  appName: string;
}): MailMessage {
  const { to, name, code, ttlMinutes, appName } = params;
  return {
    to,
    subject: `${appName}: your password reset code`,
    text: [
      `Hi ${name},`,
      '',
      `Your password reset code is: ${code}`,
      '',
      `It expires in ${ttlMinutes} minutes and can only be used once.`,
      "If you didn't request a password reset, you can ignore this email. Your password won't change.",
    ].join('\n'),
    html: layout(
      appName,
      `<p>Hi ${escapeHtml(name)},</p>
<p>Use this code to reset your password:</p>
<p style="font-size:32px;font-weight:700;letter-spacing:8px;margin:24px 0">${escapeHtml(code)}</p>
<p>It expires in ${ttlMinutes} minutes and can only be used once.</p>
<p style="color:#667085;font-size:13px">If you didn't request a password reset, you can ignore this email. Your password won't change.</p>`,
    ),
  };
}

export function passwordChangedEmail(params: { to: string; name: string; appName: string }): MailMessage {
  const { to, name, appName } = params;
  return {
    to,
    subject: `${appName}: your password was changed`,
    text: `Hi ${name},\n\nThe password for your account was just changed and you were signed out of all devices.\nIf this wasn't you, reset your password immediately.`,
    html: layout(
      appName,
      `<p>Hi ${escapeHtml(name)},</p><p>The password for your account was just changed and you were signed out of all devices.</p>
<p><strong>If this wasn't you, reset your password immediately.</strong></p>`,
    ),
  };
}
