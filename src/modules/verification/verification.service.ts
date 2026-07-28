import type { Config } from '../../config.ts'
import type { UserRepository } from '../users/users.repository.ts'
import type { EmailSender } from '../../lib/email.ts'
import type { VerificationTokenRepository } from './verification.repository.ts'
import { generateRefreshToken, hashToken } from '../../lib/tokens.ts'
import { AppError } from '../../lib/errors.ts'

export type VerificationService = ReturnType<typeof createVerificationService>

export function createVerificationService(deps: {
  verificationRepo: VerificationTokenRepository
  userRepo: UserRepository
  emailSender: EmailSender
  config: Config
}) {
  const { verificationRepo, userRepo, emailSender, config } = deps

  // Local function (not a `this` method) so `resend` can call it without
  // this-binding fragility — matches the codebase's closure style.
  async function startVerification(
    userId: string,
    email: string,
  ): Promise<void> {
    const token = generateRefreshToken()
    await verificationRepo.create({
      id: crypto.randomUUID(),
      userId,
      email,
      tokenHash: await hashToken(token),
      expiresAt: new Date(Date.now() + config.emailVerificationTtl * 1000),
    })
    const link = `${config.issuer}/verify-email?token=${token}`
    await emailSender.sendVerificationEmail(email, link)
  }

  return {
    startVerification,
    async verifyEmail(token: string): Promise<void> {
      const record = await verificationRepo.findByHash(await hashToken(token))
      if (!record) throw AppError.of('invalid_verification_link')
      if (record.consumedAt) {
        throw AppError.of('invalid_verification_link')
      }
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.of('verification_link_expired')
      }
      const user = await userRepo.findById(record.userId)
      // Stale link: the user changed their email since the link was issued.
      if (!user || user.email !== record.email) {
        throw AppError.of('invalid_verification_link')
      }
      if (!(await verificationRepo.consume(record.id))) {
        throw AppError.of('invalid_verification_link')
      }
      // Compare-and-set on the address the token was issued for: the check
      // above is not atomic with this write, so a concurrent email change must
      // lose here rather than get emailVerified stamped onto its new address.
      if (!(await userRepo.markEmailVerified(user.id, record.email))) {
        throw AppError.of('invalid_verification_link')
      }
    },
    async resend(email: string): Promise<void> {
      const user = await userRepo.findByEmail(email)
      if (!user || user.emailVerified) return
      // Bind the token to (and mail it to) the stored address, not the request
      // string: the DB lookup is collation-insensitive but verifyEmail compares
      // with `!==`, so echoing the caller's casing yields a permanently dead link.
      await startVerification(user.id, user.email)
    },
  }
}
