import { assert } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleVerificationTokenRepository } from '../../src/modules/verification/verification.repository.drizzle.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

Deno.test({
  name: 'drizzle verification token create/find/consume (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleVerificationTokenRepository(db)
    const id = crypto.randomUUID()
    const tokenHash = crypto.randomUUID().replace(/-/g, '')
    await repo.create({
      id,
      userId: crypto.randomUUID(),
      email: 'a@b.com',
      tokenHash,
      expiresAt: new Date(Date.now() + 60_000),
    })
    assert(await repo.findByHash(tokenHash))
    assert(await repo.consume(id))
    assert(!(await repo.consume(id)))
    await pool.end()
  },
})
