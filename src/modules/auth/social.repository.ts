import { duplicateKey } from '../../lib/inmemory.ts'

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
  const keyOf = (provider: string, providerAccountId: string) =>
    `${provider}:${providerAccountId}`.toLowerCase()
  return {
    findByProviderAccount(provider, providerAccountId) {
      const row = byKey.get(keyOf(provider, providerAccountId))
      return Promise.resolve(row ? { userId: row.userId } : null)
    },
    // drizzle's link() is a plain insert, so UNIQUE(provider,
    // provider_account_id) is what atomically claims a Google account against
    // a concurrent bind -- auth.service.ts relies on exactly that. A Map
    // overwrote instead, which silently moved the identity to the second
    // caller: the opposite of the guarantee the caller was told it had.
    async link(a) {
      const key = keyOf(a.provider, a.providerAccountId)
      if (byKey.has(key)) {
        throw duplicateKey(
          'social_accounts',
          'provider_provider_account_id',
          a.providerAccountId,
        )
      }
      for (const existing of byKey.values()) {
        if (existing.id === a.id) {
          throw duplicateKey('social_accounts', 'PRIMARY', a.id)
        }
      }
      byKey.set(key, { id: a.id, userId: a.userId })
      await Promise.resolve()
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
