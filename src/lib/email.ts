import type { Logger } from './logger.ts'

export type EmailSender = {
  sendVerificationEmail(to: string, link: string): Promise<void>
}

// Default dev sender: logs the verification link. Zero deps/config. Swap for a
// real SMTP/webhook implementation of EmailSender without touching callers.
export function createLogEmailSender(logger: Logger): EmailSender {
  return {
    sendVerificationEmail(to, link) {
      logger.info({ to, link }, 'verification email (log sender)')
      return Promise.resolve()
    },
  }
}
