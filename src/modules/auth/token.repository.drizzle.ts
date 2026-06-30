import { and, eq, isNull } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type { RefreshTokenRepository } from './token.repository.ts'
import { refreshTokens } from '../../db/schema.ts'

export function createDrizzleRefreshTokenRepository(
  db: Database,
): RefreshTokenRepository {
  return {
    async create(token) {
      await db.insert(refreshTokens).values({ ...token, createdAt: new Date() })
    },
    async findByHash(tokenHash) {
      const row = await db.query.refreshTokens.findFirst({
        where: eq(refreshTokens.tokenHash, tokenHash),
      })
      return row ?? null
    },
    async rotate(oldId, next) {
      // Atomic: revoke-old and insert-new commit together, so a partial failure
      // can't leave the user with a dead old token and no replacement.
      return await db.transaction(async (tx) => {
        // Conditional update: only the writer that flips an active token wins.
        const [res] = await tx.update(refreshTokens)
          .set({ revokedAt: new Date(), replacedBy: next.id })
          .where(
            and(eq(refreshTokens.id, oldId), isNull(refreshTokens.revokedAt)),
          )
        if ((res as { affectedRows: number }).affectedRows !== 1) return false
        await tx.insert(refreshTokens).values({
          ...next,
          createdAt: new Date(),
        })
        return true
      })
    },
    async revoke(id) {
      await db.update(refreshTokens).set({ revokedAt: new Date() }).where(
        eq(refreshTokens.id, id),
      )
    },
    async revokeAllForUser(userId) {
      await db.update(refreshTokens).set({ revokedAt: new Date() }).where(
        eq(refreshTokens.userId, userId),
      )
    },
  }
}
