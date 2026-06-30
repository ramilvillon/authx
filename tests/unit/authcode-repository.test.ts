import { assert, assertEquals } from '@std/assert'
import { createInMemoryAuthCodeRepository } from '../../src/modules/auth/authcode.repository.ts'

function newCode(id: string) {
  return {
    id,
    codeHash: `hash-${id}`,
    userId: 'u1',
    appServiceId: 'svc1',
    redirectUri: 'https://app.example/cb',
    codeChallenge: 'chal',
    codeChallengeMethod: 'S256',
    scope: 'a b',
    expiresAt: new Date(Date.now() + 60_000),
  }
}

Deno.test('authcode create + findByCodeHash', async () => {
  const repo = createInMemoryAuthCodeRepository()
  await repo.create(newCode('c1'))
  assertEquals((await repo.findByCodeHash('hash-c1'))?.userId, 'u1')
  assertEquals(await repo.findByCodeHash('nope'), null)
})

Deno.test('consume is single-use (second call returns false)', async () => {
  const repo = createInMemoryAuthCodeRepository()
  await repo.create(newCode('c2'))
  const id = (await repo.findByCodeHash('hash-c2'))!.id
  assert(await repo.consume(id))
  assert(!(await repo.consume(id)))
})
