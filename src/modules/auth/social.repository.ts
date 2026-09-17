export type SocialAccountRepository = {
  findByProviderAccount(
    provider: string,
    providerAccountId: string,
  ): Promise<{ userId: string } | null>
  link(account: {
    id: string
    userId: string
    provider: string
    providerAccountId: string
  }): Promise<void>
  // The schema has no foreign keys, so a deleted user's rows survive unless
  // something removes them. Returns the number of rows removed.
  deleteAllForUser(userId: string): Promise<number>
}

// In-memory test double. Mirror behavior in social.repository.drizzle.ts.
export function createInMemorySocialAccountRepository(): SocialAccountRepository {
  const byKey = new Map<string, { id: string; userId: string }>()
  return {
    findByProviderAccount(provider, providerAccountId) {
      const row = byKey.get(`${provider}:${providerAccountId}`)
      return Promise.resolve(row ? { userId: row.userId } : null)
    },
    link(a) {
      byKey.set(`${a.provider}:${a.providerAccountId}`, {
        id: a.id,
        userId: a.userId,
      })
      return Promise.resolve()
    },
    deleteAllForUser(userId) {
      let n = 0
      for (const [k, v] of byKey) {
        if (v.userId === userId) {
          byKey.delete(k)
          n++
        }
      }
      return Promise.resolve(n)
    },
  }
}
