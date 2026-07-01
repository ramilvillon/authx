import { and, eq, isNull } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type { VerificationTokenRepository } from './verification.repository.ts'
import { emailVerificationTokens } from '../../db/schema.ts'

export function createDrizzleVerificationTokenRepository(
  db: Database,
): VerificationTokenRepository {
  return {
    async create(t) {
      await db.insert(emailVerificationTokens).values({
        ...t,
        createdAt: new Date(),
      })
    },
    async findByHash(tokenHash) {
      const row = await db.query.emailVerificationTokens.findFirst({
        where: eq(emailVerificationTokens.tokenHash, tokenHash),
      })
      return row ?? null
    },
    async consume(id) {
      const [res] = await db.update(emailVerificationTokens)
        .set({ consumedAt: new Date() })
        .where(and(
          eq(emailVerificationTokens.id, id),
          isNull(emailVerificationTokens.consumedAt),
        ))
      return (res as { affectedRows: number }).affectedRows === 1
    },
  }
}
