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
  }
}
