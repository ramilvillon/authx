export type RefreshTokenRecord = {
  id: string
  userId: string
  tokenHash: string
  expiresAt: Date
  revokedAt?: Date | null
  replacedBy?: string | null
}

export type NewRefreshToken = Pick<
  RefreshTokenRecord,
  'id' | 'userId' | 'tokenHash' | 'expiresAt'
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
}

// In-memory test double for RefreshTokenRepository: lets the unit/integration
// suite run without MySQL. Mirror any behavior change in token.repository.drizzle.ts.
export function createInMemoryRefreshTokenRepository(): RefreshTokenRepository {
  const byId = new Map<string, RefreshTokenRecord>()

  return {
    create(token) {
      byId.set(token.id, { ...token, revokedAt: null, replacedBy: null })
      return Promise.resolve()
    },
    findByHash(tokenHash) {
      for (const t of byId.values()) {
        if (t.tokenHash === tokenHash) return Promise.resolve({ ...t })
      }
      return Promise.resolve(null)
    },
    rotate(oldId, next) {
      const old = byId.get(oldId)
      if (!old || old.revokedAt) return Promise.resolve(false)
      byId.set(oldId, { ...old, revokedAt: new Date(), replacedBy: next.id })
      byId.set(next.id, { ...next, revokedAt: null, replacedBy: null })
      return Promise.resolve(true)
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
  }
}
