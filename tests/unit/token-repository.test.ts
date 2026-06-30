import { assert, assertEquals } from '@std/assert'
import { createInMemoryRefreshTokenRepository } from '../../src/modules/auth/token.repository.ts'

Deno.test('store, find, rotate atomically', async () => {
  const repo = createInMemoryRefreshTokenRepository()
  const future = new Date(Date.now() + 10000)
  await repo.create({
    id: 't1',
    userId: 'u1',
    tokenHash: 'h1',
    expiresAt: future,
  })
  assertEquals((await repo.findByHash('h1'))?.id, 't1')

  const ok = await repo.rotate('t1', {
    id: 't2',
    userId: 'u1',
    tokenHash: 'h2',
    expiresAt: future,
  })
  assertEquals(ok, true)
  // old token is now revoked (still findable for reuse detection)
  assert((await repo.findByHash('h1'))?.revokedAt != null)
  assert((await repo.findByHash('h2'))?.revokedAt == null)
})

Deno.test('rotating an already-revoked token loses the race (returns false)', async () => {
  const repo = createInMemoryRefreshTokenRepository()
  const future = new Date(Date.now() + 10000)
  await repo.create({
    id: 't1',
    userId: 'u1',
    tokenHash: 'h1',
    expiresAt: future,
  })
  await repo.rotate('t1', {
    id: 't2',
    userId: 'u1',
    tokenHash: 'h2',
    expiresAt: future,
  })

  const second = await repo.rotate('t1', {
    id: 't3',
    userId: 'u1',
    tokenHash: 'h3',
    expiresAt: future,
  })
  assertEquals(second, false)
})

Deno.test('revokeAllForUser revokes every token for the user', async () => {
  const repo = createInMemoryRefreshTokenRepository()
  const future = new Date(Date.now() + 10000)
  await repo.create({
    id: 't1',
    userId: 'u1',
    tokenHash: 'h1',
    expiresAt: future,
  })
  await repo.create({
    id: 't2',
    userId: 'u1',
    tokenHash: 'h2',
    expiresAt: future,
  })
  await repo.revokeAllForUser('u1')
  assert((await repo.findByHash('h1'))?.revokedAt != null)
  assert((await repo.findByHash('h2'))?.revokedAt != null)
})
