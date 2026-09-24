import { ciEquals, duplicateKey } from '../../lib/inmemory.ts'

export type TotpRecord = {
  userId: string
  secret: string
  enabledAt: Date | null
  lastStep: number
}

type RecoveryCodeRow = {
  id: string
  userId: string
  codeHash: string
  usedAt: Date | null
}

// Single use is enforced by the storage, not by the caller reading first:
// enable, advanceStep and consumeRecoveryCode are each ONE conditional update
// in MySQL, so two parallel requests cannot both win.
export type TotpRepository = {
  find(userId: string): Promise<TotpRecord | null>
  // Inserts a pending row. Throws a duplicate-key error if ANY row exists.
  createPending(userId: string, secret: string): Promise<void>
  // Removes the row only while it is pending. Returns rows removed.
  deletePending(userId: string): Promise<number>
  // Atomic: pending -> enabled. false = not pending (missing or already on).
  enable(userId: string, step: number, at: Date): Promise<boolean>
  // Atomic replay guard: true only if step > lastStep, which it then records.
  advanceStep(userId: string, step: number): Promise<boolean>
  replaceRecoveryCodes(userId: string, codeHashes: string[]): Promise<void>
  // Atomic single use. false = unknown or already used.
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>
  // Both tables. Returns total rows removed.
  deleteAllForUser(userId: string): Promise<number>
}

// In-memory test double. Mirror behavior in totp.repository.drizzle.ts.
export function createInMemoryTotpRepository(): TotpRepository {
  const totp = new Map<string, TotpRecord>()
  let codes: RecoveryCodeRow[] = []
  return {
    find(userId) {
      const row = totp.get(userId)
      return Promise.resolve(row ? { ...row } : null)
    },
    createPending(userId, secret) {
      if (totp.has(userId)) {
        return Promise.reject(duplicateKey('user_totp', 'PRIMARY', userId))
      }
      totp.set(userId, { userId, secret, enabledAt: null, lastStep: 0 })
      return Promise.resolve()
    },
    deletePending(userId) {
      const row = totp.get(userId)
      if (!row || row.enabledAt) return Promise.resolve(0)
      totp.delete(userId)
      return Promise.resolve(1)
    },
    enable(userId, step, at) {
      const row = totp.get(userId)
      if (!row || row.enabledAt) return Promise.resolve(false)
      totp.set(userId, { ...row, enabledAt: at, lastStep: step })
      return Promise.resolve(true)
    },
    advanceStep(userId, step) {
      const row = totp.get(userId)
      if (!row || row.lastStep >= step) return Promise.resolve(false)
      totp.set(userId, { ...row, lastStep: step })
      return Promise.resolve(true)
    },
    replaceRecoveryCodes(userId, codeHashes) {
      codes = codes.filter((c) => c.userId !== userId)
      for (const codeHash of codeHashes) {
        if (
          codes.some((c) =>
            c.userId === userId && ciEquals(c.codeHash, codeHash)
          )
        ) {
          return Promise.reject(
            duplicateKey('totp_recovery_codes', 'user_id_code_hash', codeHash),
          )
        }
        codes.push({ id: crypto.randomUUID(), userId, codeHash, usedAt: null })
      }
      return Promise.resolve()
    },
    consumeRecoveryCode(userId, codeHash) {
      const row = codes.find((c) =>
        c.userId === userId && ciEquals(c.codeHash, codeHash) && !c.usedAt
      )
      if (!row) return Promise.resolve(false)
      row.usedAt = new Date()
      return Promise.resolve(true)
    },
    deleteAllForUser(userId) {
      const before = codes.length
      codes = codes.filter((c) => c.userId !== userId)
      const n = (before - codes.length) + (totp.delete(userId) ? 1 : 0)
      return Promise.resolve(n)
    },
  }
}
