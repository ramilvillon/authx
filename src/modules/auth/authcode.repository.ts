export type AuthCodeRecord = {
  id: string
  codeHash: string
  userId: string
  appServiceId: string
  redirectUri: string
  codeChallenge: string
  codeChallengeMethod: string
  scope: string
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
}

// In-memory test double. Mirror behavior in authcode.repository.drizzle.ts.
export function createInMemoryAuthCodeRepository(): AuthCodeRepository {
  const byId = new Map<string, AuthCodeRecord>()
  return {
    create(c) {
      byId.set(c.id, { ...c, consumedAt: null })
      return Promise.resolve()
    },
    findByCodeHash(codeHash) {
      for (const c of byId.values()) {
        if (c.codeHash === codeHash) return Promise.resolve({ ...c })
      }
      return Promise.resolve(null)
    },
    consume(id) {
      const c = byId.get(id)
      if (!c || c.consumedAt) return Promise.resolve(false)
      byId.set(id, { ...c, consumedAt: new Date() })
      return Promise.resolve(true)
    },
  }
}
