import type { TotpRecord, TotpRepository } from './totp.repository.ts'
import type { UserRepository } from '../users/users.repository.ts'
import { AppError } from '../../lib/errors.ts'
import { hashToken } from '../../lib/tokens.ts'
import { verifyPassword } from '../../lib/password.ts'
import {
  generateRecoveryCodes,
  generateSecret,
  importEncryptionKey,
  matchStep,
  normalizeRecoveryCode,
  openSecret,
  otpauthUri,
  sealSecret,
  toBase32,
} from '../../lib/totp.ts'

export type TotpService = ReturnType<typeof createTotpService>

export function createTotpService(deps: {
  totpRepo: TotpRepository
  userRepo: UserRepository
  issuer: string
  // '' = not configured.
  encryptionKey: string
}) {
  const { totpRepo, userRepo } = deps
  // Imported once, lazily: makeTestDeps is synchronous, so this cannot be
  // awaited at construction time.
  const key = deps.encryptionKey
    ? importEncryptionKey(deps.encryptionKey)
    : null

  function requireKey(): Promise<CryptoKey> {
    if (!key) throw AppError.of('totp_not_configured')
    return key
  }

  // null when the secret cannot be opened: no key configured (it was removed
  // after users enrolled), or a value sealed under another key. The caller
  // treats that as a wrong code -- fail closed; recovery codes still work.
  async function secretOf(
    row: TotpRecord,
  ): Promise<Uint8Array<ArrayBuffer> | null> {
    if (!key) return null
    try {
      return await openSecret(await key, row.secret)
    } catch {
      return null
    }
  }

  const hashRecoveryCode = (input: string) =>
    hashToken(normalizeRecoveryCode(input))

  async function verify(userId: string, input: string): Promise<boolean> {
    const row = await totpRepo.find(userId)
    if (!row?.enabledAt) return false
    const trimmed = input.trim()
    if (/^\d{6}$/.test(trimmed)) {
      const secret = await secretOf(row)
      const step = secret && await matchStep(secret, trimmed)
      // advanceStep is the replay guard: it accepts only a step later than
      // the last one accepted, atomically.
      return step != null && await totpRepo.advanceStep(userId, step)
    }
    return totpRepo.consumeRecoveryCode(userId, await hashRecoveryCode(trimmed))
  }

  return {
    async isEnabled(userId: string): Promise<boolean> {
      return (await totpRepo.find(userId))?.enabledAt != null
    },

    async startSetup(
      userId: string,
      currentPassword: string,
    ): Promise<{ secret: string; otpauth_uri: string }> {
      const k = await requireKey()
      const user = await userRepo.findById(userId)
      if (!user) throw AppError.of('user_not_found')
      if (user.email === null) throw AppError.of('totp_guest_forbidden')
      // A bearer token is held by every app the user signed into, and this
      // token may be for any of them. Without a password, a stolen one could
      // enrol its own authenticator, keep the recovery codes, and lock the
      // owner out. Same rule as a password change: a null hash (Google-only
      // account) has nothing to prove against, so it is refused too.
      if (
        user.passwordHash === null ||
        !await verifyPassword(currentPassword, user.passwordHash)
      ) {
        throw AppError.of('invalid_credentials')
      }
      if ((await totpRepo.find(userId))?.enabledAt) {
        throw AppError.of('totp_already_enabled')
      }
      const secret = generateSecret()
      // Delete-then-insert rather than an upsert: deletePending never touches
      // an enabled row, so if a confirm lands between the check above and
      // here, the insert hits the primary key instead of silently turning
      // the user's 2FA back into a pending setup.
      await totpRepo.deletePending(userId)
      try {
        await totpRepo.createPending(userId, await sealSecret(k, secret))
      } catch (err) {
        // createPending only throws on the primary key, but distinguishing
        // that from a transient failure by sniffing the driver's error code
        // would couple this service to the driver. Re-read instead: if a
        // confirm won the race while we were sealing the secret, the row is
        // now enabled and that IS the race this guards against. Anything
        // else (a dropped connection, etc.) is not ours to reinterpret.
        if ((await totpRepo.find(userId))?.enabledAt) {
          throw AppError.of('totp_already_enabled')
        }
        throw err
      }
      const b32 = toBase32(secret)
      return {
        secret: b32,
        otpauth_uri: otpauthUri(
          new URL(deps.issuer).host,
          user.email ?? user.username ?? userId,
          b32,
        ),
      }
    },

    async confirm(
      userId: string,
      code: string,
    ): Promise<{ recovery_codes: string[] }> {
      await requireKey()
      const row = await totpRepo.find(userId)
      if (!row) throw AppError.of('totp_not_pending')
      if (row.enabledAt) throw AppError.of('totp_already_enabled')
      const secret = await secretOf(row)
      const step = secret && await matchStep(secret, code.trim())
      if (step == null) throw AppError.of('totp_invalid_code')
      // Records the step, so the code just used cannot also sign in.
      if (!(await totpRepo.enable(userId, step, new Date()))) {
        throw AppError.of('totp_already_enabled')
      }
      const codes = generateRecoveryCodes()
      await totpRepo.replaceRecoveryCodes(
        userId,
        await Promise.all(codes.map(hashRecoveryCode)),
      )
      return { recovery_codes: codes }
    },

    verify,

    async disable(userId: string, proof: string): Promise<void> {
      await requireKey()
      // Mirrors startSetup: a service token names no user row, so it must get
      // the same 404 every other /users/me/totp* route gives it, not the
      // 401 that "verify failed" would produce for a row that never existed.
      // A 404 here is not counted by throttleFailedTotpProofs (401-only), so
      // this adds no new way to probe past the limiter.
      if (!(await userRepo.findById(userId))) {
        throw AppError.of('user_not_found')
      }
      if (!(await verify(userId, proof))) {
        throw AppError.of('invalid_credentials')
      }
      await totpRepo.deleteAllForUser(userId)
    },

    // Operator path (lost device AND lost codes). No proof by design: the
    // route requires users:update:any, which can already reset the password.
    // No key needed either: it only deletes rows, and it is the recovery path
    // when TOTP_ENCRYPTION_KEY has been removed (login still asks enrolled
    // users for a code, since isEnabled ignores the key).
    async reset(userId: string): Promise<void> {
      await totpRepo.deleteAllForUser(userId)
    },
  }
}
