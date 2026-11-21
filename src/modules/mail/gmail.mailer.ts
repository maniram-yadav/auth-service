import nodemailer, { type Transporter } from 'nodemailer';

import type { Mailer, MailMessage } from './mailer.js';

export interface GmailOAuth2Config {
  /** Gmail / Google Workspace address the mail is sent from. */
  user: string;
  clientId: string;
  clientSecret: string;
  /** Long-lived refresh token with the https://mail.google.com/ scope. */
  refreshToken: string;
  from?: string | undefined;
}

/**
 * Sends mail through Gmail SMTP authenticated with OAuth2 (XOAUTH2) using a Google Cloud
 * OAuth client id / secret. Nodemailer exchanges the refresh token for short-lived access
 * tokens automatically and renews them when they expire.
 */
export class GmailMailer implements Mailer {
  private readonly transporter: Transporter;
  private readonly from: string;

  constructor(config: GmailOAuth2Config) {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: config.user,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        refreshToken: config.refreshToken,
      },
    });
    this.from = config.from ?? config.user;
  }

  async send(message: MailMessage): Promise<void> {
    const { from, ...rest } = message;
    await this.transporter.sendMail({ ...rest, from: from ?? this.from });
  }

  async verify(): Promise<void> {
    await this.transporter.verify();
  }
}
