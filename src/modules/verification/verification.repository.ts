export type VerificationTokenRecord = {
  id: string
  userId: string
  email: string
  tokenHash: string
  expiresAt: Date
  consumedAt?: Date | null
}

export type NewVerificationToken = Omit<VerificationTokenRecord, 'consumedAt'>

export type VerificationTokenRepository = {
  create(t: NewVerificationToken): Promise<void>
  // Returns the row regardless of consumed/expired so the caller distinguishes states.
  findByHash(tokenHash: string): Promise<VerificationTokenRecord | null>
  // Atomic single-use; false = already consumed.
  consume(id: string): Promise<boolean>
}

// In-memory test double. Mirror behavior in verification.repository.drizzle.ts.
export function createInMemoryVerificationTokenRepository(): VerificationTokenRepository {
  const byId = new Map<string, VerificationTokenRecord>()
  return {
    create(t) {
      byId.set(t.id, { ...t, consumedAt: null })
      return Promise.resolve()
    },
    findByHash(tokenHash) {
      for (const t of byId.values()) {
        if (t.tokenHash === tokenHash) return Promise.resolve({ ...t })
      }
      return Promise.resolve(null)
    },
    consume(id) {
      const t = byId.get(id)
      if (!t || t.consumedAt) return Promise.resolve(false)
      byId.set(id, { ...t, consumedAt: new Date() })
      return Promise.resolve(true)
    },
  }
}
