import { and, eq, gt, isNull } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type { SessionRepository } from './session.repository.ts'
import { sessions } from '../../db/schema.ts'

export function createDrizzleSessionRepository(
  db: Database,
): SessionRepository {
  return {
    async create(s) {
      await db.insert(sessions).values({ ...s, createdAt: new Date() })
    },
    async findActiveByTokenHash(tokenHash) {
      const row = await db.query.sessions.findFirst({
        where: and(
          eq(sessions.tokenHash, tokenHash),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, new Date()),
        ),
      })
      return row ?? null
    },
    async revoke(id) {
      await db.update(sessions).set({ revokedAt: new Date() }).where(
        eq(sessions.id, id),
      )
    },
  }
}
