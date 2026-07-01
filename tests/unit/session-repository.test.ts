import { assertEquals } from '@std/assert'
import { createInMemorySessionRepository } from '../../src/modules/auth/session.repository.ts'

Deno.test('session create + findActiveByTokenHash + revoke', async () => {
  const repo = createInMemorySessionRepository()
  await repo.create({
    id: 's1',
    userId: 'u1',
    tokenHash: 'h1',
    expiresAt: new Date(Date.now() + 60_000),
  })
  assertEquals((await repo.findActiveByTokenHash('h1'))?.userId, 'u1')
  await repo.revoke('s1')
  assertEquals(await repo.findActiveByTokenHash('h1'), null)
})

Deno.test('expired session is not active', async () => {
  const repo = createInMemorySessionRepository()
  await repo.create({
    id: 's2',
    userId: 'u2',
    tokenHash: 'h2',
    expiresAt: new Date(Date.now() - 1000),
  })
  assertEquals(await repo.findActiveByTokenHash('h2'), null)
})
