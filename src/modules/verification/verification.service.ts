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
      if (!record) throw AppError.badRequest('invalid verification link')
      if (record.consumedAt) {
        throw AppError.badRequest('invalid verification link')
      }
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.badRequest('verification link expired')
      }
      const user = await userRepo.findById(record.userId)
      // Stale link: the user changed their email since the link was issued.
      if (!user || user.email !== record.email) {
        throw AppError.badRequest('invalid verification link')
      }
      if (!(await verificationRepo.consume(record.id))) {
        throw AppError.badRequest('invalid verification link')
      }
      await userRepo.update(user.id, { emailVerified: true })
    },
    async resend(email: string): Promise<void> {
      const user = await userRepo.findByEmail(email)
      if (!user || user.emailVerified) return
      await startVerification(user.id, email)
    },
  }
}
