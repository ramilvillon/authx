// Redemption is purpose-scoped: a token is only ever valid at the path that
// matches the purpose it was minted for.
export type TokenPurpose =
  | 'verify_email'
  | 'email_change'
  | 'account_deletion'
  | 'password_reset'

export type VerificationTokenRecord = {
  id: string
  userId: string
  email: string
  purpose: TokenPurpose
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
  // No foreign keys in the schema: a deleted user's rows survive unless
  // something removes them. Returns the number of rows removed.
  deleteAllForUser(userId: string): Promise<number>
  // Rows whose expiresAt is older than `cutoff`. The caller sets the cutoff
  // from a retention window, NOT from `now`: several code paths read an
  // already-dead row to detect replay, so deleting on expiry would silently
  // disable that. Returns the number of rows removed.
  deleteExpiredBefore(cutoff: Date): Promise<number>
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
