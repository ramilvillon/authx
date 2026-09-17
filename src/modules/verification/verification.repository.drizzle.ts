import { and, eq, isNull, lt } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type {
  TokenPurpose,
  VerificationTokenRepository,
} from './verification.repository.ts'
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
      // `purpose` is a varchar in MySQL, so narrow it at the boundary. An
      // unrecognised value stays unrecognised and every purpose check rejects
      // it, which is the safe direction.
      return row ? { ...row, purpose: row.purpose as TokenPurpose } : null
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
    async deleteAllForUser(userId) {
      const [res] = await db.delete(emailVerificationTokens).where(
        eq(emailVerificationTokens.userId, userId),
      )
      return (res as { affectedRows: number }).affectedRows
    },
    async deleteExpiredBefore(cutoff) {
      const [res] = await db.delete(emailVerificationTokens).where(
        lt(emailVerificationTokens.expiresAt, cutoff),
      )
      return (res as { affectedRows: number }).affectedRows
    },
  }
}
