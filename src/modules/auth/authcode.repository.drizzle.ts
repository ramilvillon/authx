import { and, eq, isNull } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type { AuthCodeRepository } from './authcode.repository.ts'
import { authorizationCodes } from '../../db/schema.ts'

export function createDrizzleAuthCodeRepository(
  db: Database,
): AuthCodeRepository {
  return {
    async create(c) {
      await db.insert(authorizationCodes).values({
        ...c,
        createdAt: new Date(),
      })
    },
    async findByCodeHash(codeHash) {
      const row = await db.query.authorizationCodes.findFirst({
        where: eq(authorizationCodes.codeHash, codeHash),
      })
      return row ?? null
    },
    async consume(id) {
      // Conditional update: only the writer that flips an unconsumed code wins.
      const [res] = await db.update(authorizationCodes)
        .set({ consumedAt: new Date() })
        .where(and(
          eq(authorizationCodes.id, id),
          isNull(authorizationCodes.consumedAt),
        ))
      return (res as { affectedRows: number }).affectedRows === 1
    },
  }
}
