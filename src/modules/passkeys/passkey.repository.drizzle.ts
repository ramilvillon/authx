import { and, eq, gt, isNull, lt } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type { PasskeyRecord, PasskeyRepository } from './passkey.repository.ts'
import { passkeys, webauthnChallenges } from '../../db/schema.ts'

const affected = (res: unknown) =>
  (res as { affectedRows: number }).affectedRows

const toRecord = (r: typeof passkeys.$inferSelect): PasskeyRecord => ({
  ...r,
  transports: r.transports ? r.transports.split(',') : [],
})

export function createDrizzlePasskeyRepository(
  db: Database,
): PasskeyRepository {
  return {
    async create(row) {
      await db.insert(passkeys).values({
        ...row,
        transports: row.transports.join(','),
      })
    },
    async findByCredentialIdHash(hash) {
      const [r] = await db.select().from(passkeys).where(
        eq(passkeys.credentialIdHash, hash),
      ).limit(1)
      return r ? toRecord(r) : null
    },
    async listForUser(userId) {
      return (await db.select().from(passkeys).where(
        eq(passkeys.userId, userId),
      )).map(toRecord)
    },
    async recordUse(id, counter, at) {
      await db.update(passkeys).set({ counter, lastUsedAt: at }).where(
        eq(passkeys.id, id),
      )
    },
    async delete(userId, id) {
      const [res] = await db.delete(passkeys).where(
        and(eq(passkeys.id, id), eq(passkeys.userId, userId)),
      )
      return affected(res) === 1
    },
    async createChallenge(c) {
      await db.insert(webauthnChallenges).values({
        id: crypto.randomUUID(),
        ...c,
        consumedAt: null,
      })
    },
    async consumeChallenge(challengeHash, purpose, userId, now) {
      const [res] = await db.update(webauthnChallenges)
        .set({ consumedAt: now })
        .where(and(
          eq(webauthnChallenges.challengeHash, challengeHash),
          eq(webauthnChallenges.purpose, purpose),
          userId === null
            ? isNull(webauthnChallenges.userId)
            : eq(webauthnChallenges.userId, userId),
          isNull(webauthnChallenges.consumedAt),
          gt(webauthnChallenges.expiresAt, now),
        ))
      return affected(res) === 1
    },
    async deleteExpiredChallengesBefore(cutoff) {
      const [res] = await db.delete(webauthnChallenges).where(
        lt(webauthnChallenges.expiresAt, cutoff),
      )
      return affected(res)
    },
    async deleteAllForUser(userId) {
      const [a] = await db.delete(passkeys).where(eq(passkeys.userId, userId))
      const [b] = await db.delete(webauthnChallenges).where(
        eq(webauthnChallenges.userId, userId),
      )
      return affected(a) + affected(b)
    },
    async deleteAllPasskeysForUser(userId) {
      const [res] = await db.delete(passkeys).where(
        eq(passkeys.userId, userId),
      )
      return affected(res)
    },
  }
}
