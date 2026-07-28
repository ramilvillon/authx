import type { Logger } from './logger.ts'

export type EmailSender = {
  sendVerificationEmail(to: string, link: string): Promise<void>
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
    sendVerificationEmail(to, link) {
      if (logLinks) {
        logger.info({ to, link }, 'verification email (log sender)')
      } else {
        logger.info('verification email (log sender; EMAIL_LOG_LINKS=false)')
      }
      return Promise.resolve()
    },
  }
}
