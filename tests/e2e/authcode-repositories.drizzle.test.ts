import { assert, assertEquals } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleSessionRepository } from '../../src/modules/auth/session.repository.drizzle.ts'
import { createDrizzleAuthCodeRepository } from '../../src/modules/auth/authcode.repository.drizzle.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

Deno.test({
  name: 'drizzle session repo create/find/revoke (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleSessionRepository(db)
    const id = crypto.randomUUID()
    const tokenHash = crypto.randomUUID().replace(/-/g, '')
    await repo.create({
      id,
      userId: crypto.randomUUID(),
      tokenHash,
      expiresAt: new Date(Date.now() + 60_000),
    })
    assert(await repo.findActiveByTokenHash(tokenHash))
    await repo.revoke(id)
    assertEquals(await repo.findActiveByTokenHash(tokenHash), null)
    await pool.end()
  },
})

Deno.test({
  name: 'drizzle authcode repo create/find/consume (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleAuthCodeRepository(db)
    const id = crypto.randomUUID()
    const codeHash = crypto.randomUUID().replace(/-/g, '')
    await repo.create({
      id,
      codeHash,
      userId: crypto.randomUUID(),
      appServiceId: crypto.randomUUID(),
      redirectUri: 'https://app.example/cb',
      codeChallenge: 'chal',
      codeChallengeMethod: 'S256',
      scope: '',
      nonce: null,
      authTime: new Date(),
      expiresAt: new Date(Date.now() + 60_000),
    })
    assert(await repo.findByCodeHash(codeHash))
    assert(await repo.consume(id))
    assert(!(await repo.consume(id)))
    await pool.end()
  },
})
