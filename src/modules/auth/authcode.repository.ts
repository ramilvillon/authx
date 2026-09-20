import { ciEquals, duplicateKey } from '../../lib/inmemory.ts'

export type AuthCodeRecord = {
  id: string
  codeHash: string
  userId: string
  appServiceId: string
  redirectUri: string
  codeChallenge: string
  codeChallengeMethod: string
  scope: string
  nonce: string | null
  authTime: Date
  expiresAt: Date
  consumedAt?: Date | null
}

export type NewAuthCode = Omit<AuthCodeRecord, 'consumedAt'>

export type AuthCodeRepository = {
  create(c: NewAuthCode): Promise<void>
  // Returns the row regardless of consumed/expired so callers can detect replay.
  findByCodeHash(codeHash: string): Promise<AuthCodeRecord | null>
  // Atomically marks consumed only if not already consumed; false = already
  // consumed (replay / lost race).
  consume(id: string): Promise<boolean>
  // No foreign keys in the schema: a deleted user's rows survive unless
  // something removes them. Returns the number of rows removed.
  deleteAllForUser(userId: string): Promise<number>
  // Rows whose expiresAt is older than `cutoff`. The caller sets the cutoff
  // from a retention window, NOT from `now`: several code paths read an
  // already-dead row to detect replay, so deleting on expiry would silently
  // disable that. Returns the number of rows removed.
  deleteExpiredBefore(cutoff: Date): Promise<number>
}

// In-memory test double. Mirror behavior in authcode.repository.drizzle.ts.
export function createInMemoryAuthCodeRepository(): AuthCodeRepository {
  const byId = new Map<string, AuthCodeRecord>()
  return {
    async create(c) {
      for (const existing of byId.values()) {
        if (existing.id === c.id) {
          throw duplicateKey('authorization_codes', 'PRIMARY', c.id)
        }
        if (ciEquals(existing.codeHash, c.codeHash)) {
          throw duplicateKey('authorization_codes', 'code_hash', c.codeHash)
        }
      }
      byId.set(c.id, { ...c, consumedAt: null })
      await Promise.resolve()
    },
    findByCodeHash(codeHash) {
      for (const c of byId.values()) {
        if (ciEquals(c.codeHash, codeHash)) return Promise.resolve({ ...c })
      }
      return Promise.resolve(null)
    },
    consume(id) {
      const c = byId.get(id)
      if (!c || c.consumedAt) return Promise.resolve(false)
      byId.set(id, { ...c, consumedAt: new Date() })
      return Promise.resolve(true)
    },
    deleteAllForUser(userId) {
      let n = 0
      for (const [k, v] of byId) {
        if (v.userId === userId) {
          byId.delete(k)
          n++
        }
      }
      return Promise.resolve(n)
    },
    deleteExpiredBefore(cutoff) {
      let n = 0
      for (const [k, v] of byId) {
        if (v.expiresAt.getTime() < cutoff.getTime()) {
          byId.delete(k)
          n++
        }
      }
      return Promise.resolve(n)
    },
  }
}
