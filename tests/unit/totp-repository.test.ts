import { assert, assertEquals, assertRejects } from '@std/assert'
import { createInMemoryTotpRepository } from '../../src/modules/mfa/totp.repository.ts'

const U = 'user-1'

Deno.test('createPending refuses a second row for the same user', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.createPending(U, 'v1:a:b')
  await assertRejects(() => repo.createPending(U, 'v1:c:d'), Error, 'duplicate')
})

Deno.test('deletePending removes a pending row but never an enabled one', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.createPending(U, 'v1:a:b')
  assertEquals(await repo.deletePending(U), 1)
  await repo.createPending(U, 'v1:a:b')
  assert(await repo.enable(U, 5, new Date()))
  assertEquals(await repo.deletePending(U), 0)
  assert((await repo.find(U))?.enabledAt)
})

Deno.test('enable succeeds once, records the step, and refuses when not pending', async () => {
  const repo = createInMemoryTotpRepository()
  assertEquals(await repo.enable(U, 5, new Date()), false)
  await repo.createPending(U, 'v1:a:b')
  assertEquals((await repo.find(U))?.lastStep, 0)
  assertEquals(await repo.enable(U, 5, new Date()), true)
  assertEquals((await repo.find(U))?.lastStep, 5)
  assertEquals(await repo.enable(U, 6, new Date()), false)
})

Deno.test('advanceStep accepts only a later step', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.createPending(U, 'v1:a:b')
  await repo.enable(U, 5, new Date())
  assertEquals(await repo.advanceStep(U, 5), false)
  assertEquals(await repo.advanceStep(U, 4), false)
  assertEquals(await repo.advanceStep(U, 6), true)
  assertEquals(await repo.advanceStep(U, 6), false)
})

Deno.test('a recovery code is spent exactly once, even by parallel callers', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.replaceRecoveryCodes(U, ['h1', 'h2'])
  const results = await Promise.all([
    repo.consumeRecoveryCode(U, 'h1'),
    repo.consumeRecoveryCode(U, 'h1'),
  ])
  assertEquals(results.filter(Boolean).length, 1)
  assertEquals(await repo.consumeRecoveryCode(U, 'h1'), false)
  assertEquals(await repo.consumeRecoveryCode(U, 'h2'), true)
})

Deno.test('recovery codes belong to one user', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.replaceRecoveryCodes(U, ['h1'])
  assertEquals(await repo.consumeRecoveryCode('someone-else', 'h1'), false)
})

Deno.test('replaceRecoveryCodes drops the previous set', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.replaceRecoveryCodes(U, ['old'])
  await repo.replaceRecoveryCodes(U, ['new'])
  assertEquals(await repo.consumeRecoveryCode(U, 'old'), false)
  assertEquals(await repo.consumeRecoveryCode(U, 'new'), true)
})

Deno.test('deleteAllForUser removes the secret and every code', async () => {
  const repo = createInMemoryTotpRepository()
  await repo.createPending(U, 'v1:a:b')
  await repo.replaceRecoveryCodes(U, ['h1', 'h2'])
  assertEquals(await repo.deleteAllForUser(U), 3)
  assertEquals(await repo.find(U), null)
  assertEquals(await repo.consumeRecoveryCode(U, 'h1'), false)
})
