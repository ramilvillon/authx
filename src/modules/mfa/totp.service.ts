import type { TotpRecord, TotpRepository } from './totp.repository.ts'
import type { UserRepository } from '../users/users.repository.ts'
import { AppError } from '../../lib/errors.ts'
import { hashToken } from '../../lib/tokens.ts'
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
    ): Promise<{ secret: string; otpauth_uri: string }> {
      const k = await requireKey()
      const user = await userRepo.findById(userId)
      if (!user) throw AppError.of('user_not_found')
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
      } catch {
        throw AppError.of('totp_already_enabled')
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
      if (!(await verify(userId, proof))) {
        throw AppError.of('invalid_credentials')
      }
      await totpRepo.deleteAllForUser(userId)
    },

    // Operator path (lost device AND lost codes). No proof by design: the
    // route requires users:update:any, which can already reset the password.
    async reset(userId: string): Promise<void> {
      await requireKey()
      await totpRepo.deleteAllForUser(userId)
    },
  }
}
