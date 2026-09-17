export type SessionRecord = {
  id: string
  userId: string
  tokenHash: string
  expiresAt: Date
  revokedAt?: Date | null
  createdAt: Date
}

export type NewSession = Pick<
  SessionRecord,
  'id' | 'userId' | 'tokenHash' | 'expiresAt'
>

export type SessionRepository = {
  create(s: NewSession): Promise<void>
  // Active = exists, not revoked, not expired. Returns null otherwise.
  findActiveByTokenHash(tokenHash: string): Promise<SessionRecord | null>
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

// In-memory test double. Mirror behavior in session.repository.drizzle.ts.
export function createInMemorySessionRepository(): SessionRepository {
  const byId = new Map<string, SessionRecord>()
  return {
    create(s) {
      byId.set(s.id, { ...s, revokedAt: null, createdAt: new Date() })
      return Promise.resolve()
    },
    findActiveByTokenHash(tokenHash) {
      for (const s of byId.values()) {
        if (
          s.tokenHash === tokenHash && !s.revokedAt &&
          s.expiresAt.getTime() > Date.now()
        ) return Promise.resolve({ ...s })
      }
      return Promise.resolve(null)
    },
    revoke(id) {
      const s = byId.get(id)
      if (s) byId.set(id, { ...s, revokedAt: new Date() })
      return Promise.resolve()
    },
    revokeAllForUser(userId) {
      for (const [id, s] of byId) {
        if (s.userId === userId) byId.set(id, { ...s, revokedAt: new Date() })
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
