import nodemailer from 'nodemailer'
import type { Logger } from './logger.ts'
import type { Config } from '../config.ts'
import { renderEmail } from './email-templates.ts'
import type { TokenPurpose } from '../modules/verification/verification.repository.ts'

export type EmailSender = {
  // `purpose` lets a real implementation pick a template: "confirm your
  // address" and "confirm you want this account deleted" must not read alike.
  sendLink(to: string, purpose: TokenPurpose, link: string): Promise<void>
}

// Default dev sender. Zero deps/config. Swap for a real SMTP/webhook
// implementation of EmailSender without touching callers.
// The link carries a live verification token (a bearer credential) and `to` is
// PII, so neither is logged unless explicitly opted in via EMAIL_LOG_LINKS=true
// for local development. Defaults to off so it fails closed.
export function createLogEmailSender(
  logger: Logger,
  logLinks = false,
): EmailSender {
  return {
    sendLink(to, purpose, link) {
      if (logLinks) {
        logger.info({ to, purpose, link }, 'outbound link email (log sender)')
      } else {
        logger.info(
          { purpose },
          'outbound link email (log sender; EMAIL_LOG_LINKS=false)',
        )
      }
      return Promise.resolve()
    },
  }
}

// Real delivery over SMTP. nodemailer speaks STARTTLS on 587 and implicit TLS
// on 465 (SMTP_SECURE=true); it has zero dependencies and runs on Deno's node
// compatibility, the same way mysql2 already does.
//
// The transport is created once and reused: nodemailer pools nothing by
// default but re-creating it per send would re-do the TLS handshake every time.
export function createSmtpEmailSender(
  config: Config,
  logger: Logger,
): EmailSender {
  const { host, port, user, pass, secure, from } = config.smtp
  const transport = nodemailer.createTransport({
    host,
    port,
    secure,
    // A local catcher (Mailpit, MailHog) wants no auth at all; passing empty
    // credentials makes it refuse the connection.
    auth: user ? { user, pass } : undefined,
  })
  return {
    async sendLink(to, purpose, link) {
      const { subject, text, html } = renderEmail(purpose, link)
      try {
        await transport.sendMail({ from, to, subject, text, html })
        // Never log `to` or `link`: the link is a live bearer credential and
        // the address is PII. Purpose alone is enough to trace a delivery.
        logger.info({ purpose }, 'sent link email')
      } catch (err) {
        // Surfaced, not swallowed: a caller that cannot mail a reset link must
        // not report success. The message is logged without the address.
        logger.error(
          { purpose, err: err instanceof Error ? err.message : String(err) },
          'failed to send link email',
        )
        throw err
      }
    },
  }
}
