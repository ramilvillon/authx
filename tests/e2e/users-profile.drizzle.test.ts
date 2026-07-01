import { assertEquals } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleUserRepository } from '../../src/modules/users/users.repository.drizzle.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

Deno.test({
  name:
    'drizzle user profile columns + email_verified round-trip (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleUserRepository(db)
    const id = crypto.randomUUID()
    const now = new Date()
    await repo.create({
      id,
      email: `${id}@b.com`,
      passwordHash: 'h',
      createdAt: now,
      updatedAt: now,
    })
    await repo.update(id, {
      name: 'Ada L',
      givenName: 'Ada',
      emailVerified: true,
    })
    const rec = await repo.findById(id)
    assertEquals(rec?.name, 'Ada L')
    assertEquals(rec?.givenName, 'Ada')
    assertEquals(rec?.emailVerified, true)
    await repo.delete(id)
    await pool.end()
  },
})
