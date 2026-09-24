import { and, eq, isNull, lt } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import type { TotpRepository } from './totp.repository.ts'
import { totpRecoveryCodes, userTotp } from '../../db/schema.ts'

const affected = (res: unknown) =>
  (res as { affectedRows: number }).affectedRows

export function createDrizzleTotpRepository(db: Database): TotpRepository {
  return {
    async find(userId) {
      const [row] = await db.select().from(userTotp).where(
        eq(userTotp.userId, userId),
      ).limit(1)
      return row ?? null
    },
    async createPending(userId, secret) {
      await db.insert(userTotp).values({
        userId,
        secret,
        enabledAt: null,
        lastStep: 0,
      })
    },
    async deletePending(userId) {
      const [res] = await db.delete(userTotp).where(
        and(eq(userTotp.userId, userId), isNull(userTotp.enabledAt)),
      )
      return affected(res)
    },
    async enable(userId, step, at) {
      const [res] = await db.update(userTotp)
        .set({ enabledAt: at, lastStep: step })
        .where(and(eq(userTotp.userId, userId), isNull(userTotp.enabledAt)))
      return affected(res) === 1
    },
    async advanceStep(userId, step) {
      const [res] = await db.update(userTotp)
        .set({ lastStep: step })
        .where(and(eq(userTotp.userId, userId), lt(userTotp.lastStep, step)))
      return affected(res) === 1
    },
    // ponytail: delete-then-insert without a transaction. Only confirm calls
    // this, once per enrollment; a crash between the two leaves an enabled
    // account with no recovery codes, which disable-and-re-enable repairs.
    async replaceRecoveryCodes(userId, codeHashes) {
      await db.delete(totpRecoveryCodes).where(
        eq(totpRecoveryCodes.userId, userId),
      )
      if (codeHashes.length === 0) return
      await db.insert(totpRecoveryCodes).values(
        codeHashes.map((codeHash) => ({
          id: crypto.randomUUID(),
          userId,
          codeHash,
          usedAt: null,
        })),
      )
    },
    async consumeRecoveryCode(userId, codeHash) {
      const [res] = await db.update(totpRecoveryCodes)
        .set({ usedAt: new Date() })
        .where(and(
          eq(totpRecoveryCodes.userId, userId),
          eq(totpRecoveryCodes.codeHash, codeHash),
          isNull(totpRecoveryCodes.usedAt),
        ))
      return affected(res) === 1
    },
    async deleteAllForUser(userId) {
      const [codes] = await db.delete(totpRecoveryCodes).where(
        eq(totpRecoveryCodes.userId, userId),
      )
      const [totp] = await db.delete(userTotp).where(
        eq(userTotp.userId, userId),
      )
      return affected(codes) + affected(totp)
    },
  }
}
