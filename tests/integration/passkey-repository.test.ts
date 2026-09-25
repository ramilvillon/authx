import { assert, assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'
import type { PasskeyRecord } from '../../src/modules/passkeys/passkey.repository.ts'

const row = (over: Partial<PasskeyRecord> = {}): PasskeyRecord => ({
  id: crypto.randomUUID(),
  userId: 'u-1',
  credentialId: 'Y3JlZA',
  credentialIdHash: 'a'.repeat(64),
  publicKey: 'cGs',
  counter: 0,
  transports: ['internal', 'hybrid'],
  aaguid: '00000000-0000-0000-0000-000000000000',
  backedUp: true,
  createdAt: new Date(Math.floor(Date.now() / 1000) * 1000),
  lastUsedAt: null,
  ...over,
})

Deno.test('a passkey round-trips, transports included', async () => {
  const { passkeyRepo } = makeTestDeps()
  const r = row()
  await passkeyRepo.create(r)
  assertEquals(await passkeyRepo.findByCredentialIdHash(r.credentialIdHash), r)
  assertEquals(await passkeyRepo.listForUser('u-1'), [r])
})

Deno.test('the credential id hash is unique', async () => {
  const { passkeyRepo } = makeTestDeps()
  await passkeyRepo.create(row())
  await assertRejects(() => passkeyRepo.create(row({ userId: 'u-2' })))
})

Deno.test('recordUse stores the counter and the time', async () => {
  const { passkeyRepo } = makeTestDeps()
  const r = row()
  await passkeyRepo.create(r)
  const at = new Date(Math.floor(Date.now() / 1000) * 1000)
  await passkeyRepo.recordUse(r.id, 7, at)
  const got = await passkeyRepo.findByCredentialIdHash(r.credentialIdHash)
  assertEquals([got?.counter, got?.lastUsedAt], [7, at])
})

Deno.test("delete removes only the owner's row", async () => {
  const { passkeyRepo } = makeTestDeps()
  const r = row()
  await passkeyRepo.create(r)
  assertEquals(await passkeyRepo.delete('u-2', r.id), false)
  assertEquals(await passkeyRepo.delete('u-1', r.id), true)
  assertEquals(await passkeyRepo.listForUser('u-1'), [])
})

Deno.test('a challenge is consumed once, for its purpose and user, before expiry', async () => {
  const { passkeyRepo } = makeTestDeps()
  const now = new Date()
  const later = new Date(now.getTime() + 60_000)
  await passkeyRepo.createChallenge({
    challengeHash: 'b'.repeat(64),
    purpose: 'register',
    userId: 'u-1',
    expiresAt: later,
  })
  assertEquals(
    await passkeyRepo.consumeChallenge(
      'b'.repeat(64),
      'authenticate',
      null,
      now,
    ),
    false,
  )
  assertEquals(
    await passkeyRepo.consumeChallenge('b'.repeat(64), 'register', 'u-2', now),
    false,
  )
  assert(
    await passkeyRepo.consumeChallenge('b'.repeat(64), 'register', 'u-1', now),
  )
  assertEquals(
    await passkeyRepo.consumeChallenge('b'.repeat(64), 'register', 'u-1', now),
    false,
  )
  await passkeyRepo.createChallenge({
    challengeHash: 'c'.repeat(64),
    purpose: 'authenticate',
    userId: null,
    expiresAt: new Date(now.getTime() - 1000),
  })
  assertEquals(
    await passkeyRepo.consumeChallenge(
      'c'.repeat(64),
      'authenticate',
      null,
      now,
    ),
    false,
  )
})

Deno.test('expired challenges are pruned; deleteAllForUser clears both tables', async () => {
  const { passkeyRepo } = makeTestDeps()
  const now = new Date()
  await passkeyRepo.createChallenge({
    challengeHash: 'd'.repeat(64),
    purpose: 'authenticate',
    userId: null,
    expiresAt: new Date(now.getTime() - 60_000),
  })
  assertEquals(await passkeyRepo.deleteExpiredChallengesBefore(now), 1)
  await passkeyRepo.create(row())
  await passkeyRepo.createChallenge({
    challengeHash: 'e'.repeat(64),
    purpose: 'register',
    userId: 'u-1',
    expiresAt: new Date(now.getTime() + 60_000),
  })
  assertEquals(await passkeyRepo.deleteAllForUser('u-1'), 2)
})

Deno.test('deleteAllPasskeysForUser removes only the passkeys, leaving challenges alone', async () => {
  const { passkeyRepo } = makeTestDeps()
  const now = new Date()
  await passkeyRepo.create(row())
  await passkeyRepo.createChallenge({
    challengeHash: 'f'.repeat(64),
    purpose: 'register',
    userId: 'u-1',
    expiresAt: new Date(now.getTime() + 60_000),
  })
  assertEquals(await passkeyRepo.deleteAllPasskeysForUser('u-1'), 1)
  assertEquals(await passkeyRepo.listForUser('u-1'), [])
  // The challenge row survives -- only the passkey and deleteAllForUser (the
  // purge path) touch webauthn_challenges.
  assert(
    await passkeyRepo.consumeChallenge('f'.repeat(64), 'register', 'u-1', now),
  )
})
