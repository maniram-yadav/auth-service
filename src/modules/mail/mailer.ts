export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

/** Port for sending email. Implementations: Gmail (OAuth2), console (dev), memory (tests). */
export interface Mailer {
  send(message: MailMessage): Promise<void>;
  /** Checks connectivity / credentials; used at startup. */
  verify(): Promise<void>;
}
