import { assertAcceptablePassword } from '../../lib/password-policy.ts'
import type { UserRecord, UserRepository } from './users.repository.ts'
import type {
  PublicUser,
  RegisterInput,
  UpdateUserInput,
} from './users.schema.ts'
import type { RefreshTokenRepository } from '../auth/token.repository.ts'
import type { AuthCodeRepository } from '../auth/authcode.repository.ts'
import type { SocialAccountRepository } from '../auth/social.repository.ts'
import type { OrgRepository } from '../orgs/orgs.repository.ts'
import type { VerificationTokenRepository } from '../verification/verification.repository.ts'
import type { SessionRepository } from '../auth/session.repository.ts'
import type { TotpRepository } from '../mfa/totp.repository.ts'
import type { PasskeyRepository } from '../passkeys/passkey.repository.ts'
import { hashPassword, verifyPassword } from '../../lib/password.ts'
import { generateRefreshToken } from '../../lib/tokens.ts'
import { AppError } from '../../lib/errors.ts'

export type UserService = ReturnType<typeof createUserService>

function toPublic(u: UserRecord): PublicUser {
  return {
    id: u.id,
    email: u.email,
    username: u.username ?? null,
    createdAt: u.createdAt,
  }
}

export function createUserService(deps: {
  repo: UserRepository
  tokenRepo: RefreshTokenRepository
  sessionRepo: SessionRepository
  authCodeRepo: AuthCodeRepository
  verificationRepo: VerificationTokenRepository
  socialRepo: SocialAccountRepository
  orgRepo: OrgRepository
  totpRepo: TotpRepository
  passkeyRepo: PasskeyRepository
  // Guests sign in only through the password grant.
  allowPasswordGrant: boolean
}) {
  const {
    repo,
    tokenRepo,
    sessionRepo,
    authCodeRepo,
    verificationRepo,
    socialRepo,
    orgRepo,
    totpRepo,
    passkeyRepo,
    allowPasswordGrant,
  } = deps
  return {
    async register(input: RegisterInput): Promise<PublicUser> {
      // findAnyByEmail, not findByEmail: users.email is UNIQUE, so a
      // soft-deleted row still holds the address. Checking the filtered view
      // would let this through and fail on a duplicate key at the database.
      if (await repo.findAnyByEmail(input.email)) {
        throw AppError.of('email_taken')
      }
      assertAcceptablePassword(input.password)
      const now = new Date()
      const user = await repo.create({
        id: crypto.randomUUID(),
        email: input.email,
        passwordHash: await hashPassword(input.password),
        createdAt: now,
        updatedAt: now,
      })
      // No role on registration. Roles are per-service and granted through the
      // management API -- the same reason loginWithGoogle assigns none. The old
      // global 'user' role granted nothing, was never seeded, and made the
      // drizzle assignRole throw 'role user not seeded' on every registration
      // against a real database.
      return toPublic(user)
    },
    // The player never types these: the client stores both and re-authenticates
    // with grant_type=password on every launch.
    async createGuest(
      clientId: string,
    ): Promise<{ username: string; password: string }> {
      const service = await orgRepo.findServiceByClientId(clientId)
      // Same 404 for "no such client" and "not opted in" -- neither should be
      // probeable.
      // With the password grant off, the credentials could never sign in.
      if (!allowPasswordGrant || !service || service.guestsEnabled !== true) {
        throw AppError.of('guest_accounts_disabled')
      }
      // generateRefreshToken is not refresh-specific: 32 random bytes, hex
      // encoded. Reused rather than copied so there is one entropy decision.
      const username = `guest_${generateRefreshToken().slice(0, 16)}`
      const password = generateRefreshToken()
      const now = new Date()
      const user = await repo.create({
        id: crypto.randomUUID(),
        email: null,
        username,
        passwordHash: await hashPassword(password),
        createdAt: now,
        updatedAt: now,
      })
      // Not optional: issueTokensForService refuses a non-member, so without
      // this the credential we just handed out could never obtain a token.
      // register() gets away with granting none because a registered user
      // waits for an admin; a guest has no admin step. addMember is
      // idempotent (onDuplicateKeyUpdate), so a retry is safe.
      await orgRepo.addMember({
        id: crypto.randomUUID(),
        userId: user.id,
        orgId: service.orgId,
        createdAt: now,
      })
      // No role. Roles are per-service and granted through the management API,
      // the same reason loginWithGoogle assigns none. The token carries an
      // empty scope, which requireAuth accepts.
      return { username, password }
    },
    async getById(id: string): Promise<PublicUser> {
      const u = await repo.findById(id)
      if (!u) throw AppError.of('user_not_found')
      return toPublic(u)
    },
    // `requireCurrentPassword` is not optional on purpose: every caller has to
    // say which side of the trust boundary it is on, so a new one cannot skip
    // the challenge by forgetting an argument.
    async update(
      id: string,
      input: UpdateUserInput,
      opts: { requireCurrentPassword: boolean },
    ): Promise<PublicUser> {
      const current = await repo.findById(id)
      if (!current) throw AppError.of('user_not_found')
      const patch: Partial<
        Pick<
          UserRecord,
          | 'email'
          | 'passwordHash'
          | 'emailVerified'
          | 'name'
          | 'givenName'
          | 'familyName'
          | 'picture'
        >
      > = {}
      if (input.email) {
        // users.email is UNIQUE. Without this the write reaches the driver as
        // a duplicate-key error and surfaces as a 500 -- register() and both
        // Google paths already guard with findAnyByEmail; this one did not.
        // findAnyByEmail, not findByEmail: a soft-deleted row still occupies
        // the address until the purge.
        const holder = await repo.findAnyByEmail(input.email)
        if (holder && holder.id !== id) throw AppError.of('email_taken')
        patch.email = input.email
      }
      if (input.password) {
        // A bearer token says who you are, not that you know the password it
        // was minted from. Without this challenge, anyone holding a stolen
        // token takes the account permanently. An operator acting through
        // users:update:any is exempt: they never know the password, and that
        // path is the only way back into a passwordless account.
        if (opts.requireCurrentPassword) {
          if (!input.current_password) {
            throw AppError.of('current_password_required')
          }
          // A null hash means there is nothing to prove against, so the owner's
          // request and a stolen token's request are byte-identical. Refuse
          // both rather than hand the account to whoever asks first.
          if (
            current.passwordHash === null ||
            !await verifyPassword(input.current_password, current.passwordHash)
          ) {
            throw AppError.of('invalid_credentials')
          }
        }
        assertAcceptablePassword(input.password)
        patch.passwordHash = await hashPassword(input.password)
      }
      if (input.name !== undefined) patch.name = input.name
      if (input.given_name !== undefined) patch.givenName = input.given_name
      if (input.family_name !== undefined) patch.familyName = input.family_name
      if (input.picture !== undefined) patch.picture = input.picture
      // A new email address is unverified until it is re-verified.
      if (input.email && input.email !== current.email) {
        patch.emailVerified = false
      }
      const u = await repo.update(id, patch)
      if (!u) throw AppError.of('user_not_found')
      // Credentials issued under the old password must not outlive it. Revoke
      // after the hash is stored, so the old password can no longer mint a
      // replacement in between.
      if (patch.passwordHash) {
        await tokenRepo.revokeAllForUser(id)
        await sessionRepo.revokeAllForUser(id)
        // Same reasoning as the revocations above: a passkey enrolled while
        // holding the old credentials must not outlive them either.
        await passkeyRepo.deleteAllPasskeysForUser(id)
      }
      return toPublic(u)
    },
    async remove(id: string): Promise<void> {
      // Soft delete. Account deletion is something an attacker can trigger, so
      // it must not be irreversible; `deno task db:prune` performs the real
      // erasure after the grace period. Nothing is revoked explicitly here --
      // the repository filter hides the row, and every auth path reaches a user
      // through findById/findByEmail, so tokens and sessions die with it.
      if (!(await repo.softDelete(id))) throw AppError.of('user_not_found')
    },
    // Erasure, after the grace period. Returns how many accounts were purged.
    async purgeDeletedBefore(cutoff: Date): Promise<number> {
      const ids = await repo.findDeletedBefore(cutoff)
      for (const id of ids) {
        // The schema has no foreign keys, so nothing cleans these up for us --
        // which is why F13 had to make orphaned rows inert rather than absent.
        // Satellites first, then the row: if a purge fails the account still
        // exists and the next run finishes the job, where the other order
        // would leave orphans behind with no way to find them again.
        await Promise.all([
          tokenRepo.deleteAllForUser(id),
          sessionRepo.deleteAllForUser(id),
          authCodeRepo.deleteAllForUser(id),
          verificationRepo.deleteAllForUser(id),
          socialRepo.deleteAllForUser(id),
          repo.removeAllRoles(id),
          orgRepo.removeAllMemberships(id),
          totpRepo.deleteAllForUser(id),
          passkeyRepo.deleteAllForUser(id),
        ])
        await repo.delete(id)
      }
      return ids.length
    },
    async list(): Promise<PublicUser[]> {
      return (await repo.list()).map(toPublic)
    },
    getUserRecord(id: string): Promise<UserRecord | null> {
      return repo.findById(id)
    },
  }
}
