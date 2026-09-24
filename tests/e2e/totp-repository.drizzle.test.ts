import { assert, assertEquals, assertRejects } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleTotpRepository } from '../../src/modules/mfa/totp.repository.drizzle.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

Deno.test({
  name:
    'drizzle totp repo: pending, enable, replay guard, single-use codes (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleTotpRepository(db)
    const u = crypto.randomUUID()
    try {
      await repo.createPending(u, 'v1:a:b')
      await assertRejects(() => repo.createPending(u, 'v1:c:d'))
      assertEquals(await repo.deletePending(u), 1)
      await repo.createPending(u, 'v1:a:b')
      assert(await repo.enable(u, 5, new Date()))
      assertEquals(await repo.enable(u, 6, new Date()), false)
      assertEquals(await repo.deletePending(u), 0)
      assertEquals(await repo.advanceStep(u, 5), false)
      assert(await repo.advanceStep(u, 6))

      await repo.replaceRecoveryCodes(u, ['h1', 'h2'])
      const both = await Promise.all([
        repo.consumeRecoveryCode(u, 'h1'),
        repo.consumeRecoveryCode(u, 'h1'),
      ])
      assertEquals(both.filter(Boolean).length, 1)
      assertEquals(await repo.deleteAllForUser(u), 3)
      assertEquals(await repo.find(u), null)
    } finally {
      await repo.deleteAllForUser(u)
      await pool.end()
    }
  },
})
