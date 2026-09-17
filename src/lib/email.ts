import type { Logger } from './logger.ts'
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
