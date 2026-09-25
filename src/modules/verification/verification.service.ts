import type { Config } from '../../config.ts'
import type { UserRepository } from '../users/users.repository.ts'
import type { RefreshTokenRepository } from '../auth/token.repository.ts'
import type { SessionRepository } from '../auth/session.repository.ts'
import type { PasskeyRepository } from '../passkeys/passkey.repository.ts'
import { hashPassword } from '../../lib/password.ts'
import type { EmailSender } from '../../lib/email.ts'
import {
  ACCOUNT_CHANGING_PURPOSES,
  type TokenPurpose,
  type VerificationTokenRepository,
} from './verification.repository.ts'
import { generateRefreshToken, hashToken } from '../../lib/tokens.ts'
import { assertAcceptablePassword } from '../../lib/password-policy.ts'
import { AppError } from '../../lib/errors.ts'

export type VerificationService = ReturnType<typeof createVerificationService>

export function createVerificationService(deps: {
  verificationRepo: VerificationTokenRepository
  userRepo: UserRepository
  tokenRepo: RefreshTokenRepository
  sessionRepo: SessionRepository
  passkeyRepo: PasskeyRepository
  emailSender: EmailSender
  config: Config
}) {
  const {
    verificationRepo,
    userRepo,
    tokenRepo,
    sessionRepo,
    passkeyRepo,
    emailSender,
    config,
  } = deps

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
      // A guest has no address to authorise the change from.
      if (!user.email) throw AppError.of('account_has_no_email')
      if (user.email === newEmail) return
      // Refuse here rather than at the confirm, where the token has already
      // been consumed: the owner would lose a single-use link to a conflict
      // they could see now.
      const holder = await userRepo.findAnyByEmail(newEmail)
      if (holder && holder.id !== userId) throw AppError.of('email_taken')
      await startConfirmation(userId, 'email_change', newEmail, user.email)
    },
    // Self-service account deletion: authorised from the current address, the
    // one an app service holding the user's access token cannot read.
    async startAccountDeletion(userId: string): Promise<void> {
      const user = await userRepo.findById(userId)
      if (!user) throw AppError.of('user_not_found')
      // A guest has no address to authorise the deletion from.
      if (!user.email) throw AppError.of('account_has_no_email')
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
    // Returns who and which address the link was for, so the route can follow
    // an email change with a verification link to the new address.
    async confirm(
      token: string,
    ): Promise<{ purpose: TokenPurpose; userId: string; email: string }> {
      const record = await verificationRepo.findByHash(await hashToken(token))
      // Allow-list, not a deny-list: this endpoint acts immediately, so a
      // purpose it does not handle (a password reset, which needs a form) would
      // otherwise be consumed here and burned without doing anything.
      if (
        !record ||
        (record.purpose !== 'email_change' &&
          record.purpose !== 'account_deletion')
      ) {
        throw AppError.of('invalid_verification_link')
      }
      if (record.consumedAt) throw AppError.of('invalid_verification_link')
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.of('verification_link_expired')
      }
      const user = await userRepo.findById(record.userId)
      if (!user) throw AppError.of('invalid_verification_link')
      // Before the consume, not after: the address can be taken between the
      // request and the click, and that conflict is not the owner's doing --
      // so it must not cost them the link. Re-checked rather than trusted from
      // startEmailChange for the same reason.
      if (record.purpose === 'email_change') {
        const holder = await userRepo.findAnyByEmail(record.email)
        if (holder && holder.id !== user.id) throw AppError.of('email_taken')
      }
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
        // Soft, like every other deletion path: this is the one an attacker can
        // trigger, so it must land in the grace period rather than destroy the
        // row. The satellite cascade and the real erasure both happen in
        // userService.purgeDeletedBefore once the grace period expires.
        await userRepo.softDelete(user.id)
      }
      return {
        purpose: record.purpose,
        userId: record.userId,
        email: record.email,
      }
    },
    // Always resolves, whether or not the address is registered: the response
    // must not reveal which. Mirrors `resend`.
    async startPasswordReset(email: string): Promise<void> {
      const user = await userRepo.findByEmail(email)
      if (!user) return
      // findByEmail can never return a null-email row, so this is a type
      // narrowing, not a reachable guest path -- kept anyway so this fails
      // closed rather than trusting that invariant silently.
      if (!user.email) return
      // Mail the STORED address, not the request string: the lookup is
      // collation-insensitive but the token is bound to one exact spelling.
      await startConfirmation(user.id, 'password_reset', user.email, user.email)
    },
    async resetPassword(token: string, password: string): Promise<void> {
      // Before the link is even looked up, and so before it is consumed: a
      // refused password must cost the user nothing. Consuming first would
      // burn the link and strand them (PR #35, on the email-change path).
      assertAcceptablePassword(password)
      const record = await verificationRepo.findByHash(await hashToken(token))
      if (!record || record.purpose !== 'password_reset') {
        throw AppError.of('invalid_verification_link')
      }
      if (record.consumedAt) throw AppError.of('invalid_verification_link')
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.of('verification_link_expired')
      }
      // findById filters soft-deleted rows, so a deleted account cannot reset
      // its way back into existence.
      const user = await userRepo.findById(record.userId)
      if (!user || user.email !== record.email) {
        throw AppError.of('invalid_verification_link')
      }
      // Consume before acting, so a replay loses the race.
      if (!(await verificationRepo.consume(record.id))) {
        throw AppError.of('invalid_verification_link')
      }
      // emailVerified: clicking a link delivered to this address proves control
      // of it -- the same proof /verify-email asks for.
      await userRepo.update(user.id, {
        passwordHash: await hashPassword(password),
        emailVerified: true,
      })
      // Reset is what someone reaches for BECAUSE they think they are
      // compromised. Leaving the attacker's credentials alive defeats it --
      // and an attacker who enrolled their own passkey while in the account
      // must lose it too, or the reset would not actually lock them out.
      await tokenRepo.revokeAllForUser(user.id)
      await sessionRepo.revokeAllForUser(user.id)
      await passkeyRepo.deleteAllPasskeysForUser(user.id)
      await verificationRepo.consumeAllForUser(
        user.id,
        ACCOUNT_CHANGING_PURPOSES,
      )
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
      // findByEmail can never return a null-email row, so this is a type fix,
      // not a behaviour change -- already unreachable for a guest. Keep it
      // failing closed anyway; the 204 above already hides the difference.
      if (!user.email) return
      // Bind the token to (and mail it to) the stored address, not the request
      // string: the DB lookup is collation-insensitive but verifyEmail compares
      // with `!==`, so echoing the caller's casing yields a permanently dead link.
      await startVerification(user.id, user.email)
    },
  }
}
