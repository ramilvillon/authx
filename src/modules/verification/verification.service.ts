import type { Config } from '../../config.ts'
import type { UserRepository } from '../users/users.repository.ts'
import type { EmailSender } from '../../lib/email.ts'
import type {
  TokenPurpose,
  VerificationTokenRepository,
} from './verification.repository.ts'
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
      purpose: 'verify_email',
      tokenHash: await hashToken(token),
      expiresAt: new Date(Date.now() + config.emailVerificationTtl * 1000),
    })
    const link = `${config.issuer}/verify-email?token=${token}`
    await emailSender.sendLink(email, 'verify_email', link)
  }

  // Mints a confirmation token and mails the link to `sendTo`. Callers pass the
  // account's CURRENT address as `sendTo`: that is the one an app service
  // holding the user's access token cannot read, which is the entire point of
  // confirming out of band. `email` on the row is the token's subject matter
  // (the target address for a change), not the recipient.
  async function startConfirmation(
    userId: string,
    purpose: TokenPurpose,
    email: string,
    sendTo: string,
  ): Promise<void> {
    const token = generateRefreshToken()
    await verificationRepo.create({
      id: crypto.randomUUID(),
      userId,
      email,
      purpose,
      tokenHash: await hashToken(token),
      expiresAt: new Date(Date.now() + config.emailVerificationTtl * 1000),
    })
    await emailSender.sendLink(
      sendTo,
      purpose,
      `${config.issuer}/confirm?token=${token}`,
    )
  }

  return {
    startVerification,
    // Self-service email change: authorised from the CURRENT address.
    async startEmailChange(userId: string, newEmail: string): Promise<void> {
      const user = await userRepo.findById(userId)
      if (!user) throw AppError.of('user_not_found')
      if (user.email === newEmail) return
      await startConfirmation(userId, 'email_change', newEmail, user.email)
    },
    // Self-service account deletion: authorised from the current address, the
    // one an app service holding the user's access token cannot read.
    async startAccountDeletion(userId: string): Promise<void> {
      const user = await userRepo.findById(userId)
      if (!user) throw AppError.of('user_not_found')
      await startConfirmation(
        userId,
        'account_deletion',
        user.email,
        user.email,
      )
    },
    // Redeems a confirmation link. Shared shape for every out-of-band
    // authorisation: find, assert purpose, assert fresh, consume, then act.
    // Consume happens BEFORE the effect so a replay loses the race rather than
    // repeating a destructive action.
    async confirm(token: string): Promise<TokenPurpose> {
      const record = await verificationRepo.findByHash(await hashToken(token))
      if (!record || record.purpose === 'verify_email') {
        throw AppError.of('invalid_verification_link')
      }
      if (record.consumedAt) throw AppError.of('invalid_verification_link')
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.of('verification_link_expired')
      }
      const user = await userRepo.findById(record.userId)
      if (!user) throw AppError.of('invalid_verification_link')
      if (!(await verificationRepo.consume(record.id))) {
        throw AppError.of('invalid_verification_link')
      }
      if (record.purpose === 'email_change') {
        // emailVerified resets to false inside the repo patch: confirming from
        // the old address authorises the move, it does not prove control of
        // the new address. The existing verify-email flow does that.
        if (
          !(await userRepo.update(user.id, {
            email: record.email,
            emailVerified: false,
          }))
        ) {
          throw AppError.of('invalid_verification_link')
        }
      }
      if (record.purpose === 'account_deletion') {
        // ponytail: hard delete, same as the direct route -- see the marker in
        // users.repository.drizzle.ts. Soft delete lands with the cascade work.
        await userRepo.delete(user.id)
      }
      return record.purpose
    },
    async verifyEmail(token: string): Promise<void> {
      const record = await verificationRepo.findByHash(await hashToken(token))
      // A token minted for an email change or an account deletion must not
      // redeem here, and vice versa.
      if (!record || record.purpose !== 'verify_email') {
        throw AppError.of('invalid_verification_link')
      }
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
