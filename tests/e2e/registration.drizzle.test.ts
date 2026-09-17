import { assert, assertEquals } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDeps } from '../../src/deps.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

// The in-memory user repository's assignRole just adds to a Set, while the
// drizzle one looks the role up and throws if it is missing. That difference
// is why registration could be broken against a real database while all 96
// unit and 77 integration tests passed. This is the test that catches it.
Deno.test({
  name: 'registering works against a real database (needs MySQL + seed)',
  ignore: !hasDb,
  fn: async () => {
    const config = loadConfig(Deno.env.toObject())
    const { db, pool } = createDb(config)
    const deps = await createDeps(config, db)
    const email = `reg-${crypto.randomUUID()}@b.com`

    const user = await deps.userService.register({
      email,
      password: 'pw123456',
    })

    assertEquals(user.email, email)
    assert(await deps.userService.getById(user.id))

    await deps.userService.remove(user.id)
    await deps.userService.purgeDeletedBefore(new Date(Date.now() + 60_000))
    await pool.end()
  },
})
