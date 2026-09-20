import { ciEquals, duplicateKey } from '../../lib/inmemory.ts'

export type RefreshTokenRecord = {
  id: string
  userId: string
  appServiceId: string
  tokenHash: string
  expiresAt: Date
  revokedAt?: Date | null
  replacedBy?: string | null
}

export type NewRefreshToken = Pick<
  RefreshTokenRecord,
  'id' | 'userId' | 'appServiceId' | 'tokenHash' | 'expiresAt'
>

export type RefreshTokenRepository = {
  create(token: NewRefreshToken): Promise<void>
  // Returns the row regardless of revoked/expired state, so callers can
  // distinguish "unknown token" from "known-but-revoked" (reuse detection).
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>
  // Atomically revokes `oldId` only if it is still active, then inserts `next`.
  // Returns false if `oldId` was already revoked (lost the race / replay).
  rotate(oldId: string, next: NewRefreshToken): Promise<boolean>
  revoke(id: string): Promise<void>
  revokeAllForUser(userId: string): Promise<void>
  // No foreign keys in the schema: a deleted user's rows survive unless
  // something removes them. Returns the number of rows removed.
  deleteAllForUser(userId: string): Promise<number>
  // Rows whose expiresAt is older than `cutoff`. The caller sets the cutoff
  // from a retention window, NOT from `now`: several code paths read an
  // already-dead row to detect replay, so deleting on expiry would silently
  // disable that. Returns the number of rows removed.
  deleteExpiredBefore(cutoff: Date): Promise<number>
}

// In-memory test double for RefreshTokenRepository: lets the unit/integration
// suite run without MySQL. Mirror any behavior change in token.repository.drizzle.ts.
export function createInMemoryRefreshTokenRepository(): RefreshTokenRepository {
  const byId = new Map<string, RefreshTokenRecord>()

  // refresh_tokens.token_hash is UNIQUE, which is what makes a hash collision
  // a loud error instead of one token silently shadowing another.
  function assertInsertable(t: { id: string; tokenHash: string }) {
    for (const existing of byId.values()) {
      if (existing.id === t.id) {
        throw duplicateKey('refresh_tokens', 'PRIMARY', t.id)
      }
      if (ciEquals(existing.tokenHash, t.tokenHash)) {
        throw duplicateKey('refresh_tokens', 'token_hash', t.tokenHash)
      }
    }
  }

  return {
    async create(token) {
      assertInsertable(token)
      byId.set(token.id, { ...token, revokedAt: null, replacedBy: null })
      await Promise.resolve()
    },
    findByHash(tokenHash) {
      for (const t of byId.values()) {
        if (ciEquals(t.tokenHash, tokenHash)) return Promise.resolve({ ...t })
      }
      return Promise.resolve(null)
    },
    async rotate(oldId, next) {
      const old = byId.get(oldId)
      if (!old || old.revokedAt) return await Promise.resolve(false)
      assertInsertable(next)
      byId.set(oldId, { ...old, revokedAt: new Date(), replacedBy: next.id })
      byId.set(next.id, { ...next, revokedAt: null, replacedBy: null })
      return await Promise.resolve(true)
    },
    revoke(id) {
      const t = byId.get(id)
      if (t) byId.set(id, { ...t, revokedAt: new Date() })
      return Promise.resolve()
    },
    revokeAllForUser(userId) {
      for (const [id, t] of byId) {
        if (t.userId === userId) byId.set(id, { ...t, revokedAt: new Date() })
      }
      return Promise.resolve()
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
