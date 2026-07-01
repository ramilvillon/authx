import { assert, assertEquals } from '@std/assert'
import { createInMemoryVerificationTokenRepository } from '../../src/modules/verification/verification.repository.ts'

function rec(id: string) {
  return {
    id,
    userId: 'u1',
    email: 'a@b.com',
    tokenHash: `hash-${id}`,
    expiresAt: new Date(Date.now() + 60_000),
  }
}

Deno.test('verification token create + findByHash', async () => {
  const repo = createInMemoryVerificationTokenRepository()
  await repo.create(rec('t1'))
  assertEquals((await repo.findByHash('hash-t1'))?.userId, 'u1')
  assertEquals(await repo.findByHash('nope'), null)
})

Deno.test('consume is single-use (second call false)', async () => {
  const repo = createInMemoryVerificationTokenRepository()
  await repo.create(rec('t2'))
  const id = (await repo.findByHash('hash-t2'))!.id
  assert(await repo.consume(id))
  assert(!(await repo.consume(id)))
})
