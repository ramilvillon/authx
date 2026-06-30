import { and, eq } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import { socialAccounts } from '../../db/schema.ts'
import type { SocialAccountRepository } from './social.repository.ts'

export function createDrizzleSocialAccountRepository(
  db: Database,
): SocialAccountRepository {
  return {
    async findByProviderAccount(provider, providerAccountId) {
      const row = await db.query.socialAccounts.findFirst({
        where: and(
          eq(socialAccounts.provider, provider),
          eq(socialAccounts.providerAccountId, providerAccountId),
        ),
      })
      return row ? { userId: row.userId } : null
    },
    async link(account) {
      await db.insert(socialAccounts).values({
        ...account,
        createdAt: new Date(),
      })
    },
  }
}
