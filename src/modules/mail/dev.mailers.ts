import type { Logger } from 'pino';

import type { Mailer, MailMessage } from './mailer.js';

/** Development only: prints emails to the log instead of sending them. Refused in production by env validation. */
export class ConsoleMailer implements Mailer {
  constructor(private readonly logger: Logger) {}

  async send(message: MailMessage): Promise<void> {
    this.logger.warn({ to: message.to, subject: message.subject }, `[dev mail]\n${message.text}`);
  }

  async verify(): Promise<void> {}
}

/** Keeps sent messages in memory (tests). */
export class MemoryMailer implements Mailer {
  readonly sent: MailMessage[] = [];

  async send(message: MailMessage): Promise<void> {
    this.sent.push(message);
  }

  async verify(): Promise<void> {}

  lastTo(to: string): MailMessage | undefined {
    return [...this.sent].reverse().find((m) => m.to === to);
  }

  clear(): void {
    this.sent.length = 0;
  }
}
