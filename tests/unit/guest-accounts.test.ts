import { assert, assertEquals } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'
import { claimsForScopes } from '../../src/lib/oidc.ts'
import { AppError } from '../../src/lib/errors.ts'
import { makeTestDeps } from '../helpers.ts'

function guestRow(username: string) {
  const now = new Date()
  return {
    id: crypto.randomUUID(),
    email: null,
    username,
    passwordHash: 'x',
    createdAt: now,
    updatedAt: now,
  }
}

Deno.test('findByUsername finds a guest that has no email', async () => {
  const repo = createInMemoryUserRepository()
  const created = await repo.create(guestRow('guest_abc'))
  const found = await repo.findByUsername('guest_abc')
  assertEquals(found?.id, created.id)
  assertEquals(found?.email, null)
})

Deno.test('findByUsername hides a soft-deleted guest', async () => {
  const repo = createInMemoryUserRepository()
  const created = await repo.create(guestRow('guest_gone'))
  await repo.softDelete(created.id)
  assertEquals(await repo.findByUsername('guest_gone'), null)
})

// The divergence guard. A Map compares null === null and matches; MySQL's
// `WHERE email = NULL` never does. Without an explicit guard the in-memory
// double is more permissive than the database, which is how three real bugs
// have already hidden behind a green suite.
Deno.test('an email lookup never matches a row that has no email', async () => {
  const repo = createInMemoryUserRepository()
  await repo.create(guestRow('guest_nomail'))
  assertEquals(
    await repo.findByEmail(null as unknown as string),
    null,
    'findByEmail(null) must not match a null-email row',
  )
  assertEquals(
    await repo.findAnyByEmail(null as unknown as string),
    null,
    'findAnyByEmail(null) must not match a null-email row',
  )
})

Deno.test('two guests can coexist with no email', async () => {
  const repo = createInMemoryUserRepository()
  await repo.create(guestRow('guest_one'))
  await repo.create(guestRow('guest_two'))
  assertEquals((await repo.list()).length, 2)
})

Deno.test('an account with no email emits neither email claim', () => {
  const claims = claimsForScopes(
    { email: null, emailVerified: false, updatedAt: new Date() },
    ['email', 'profile'],
  )
  assertEquals('email' in claims, false, 'no email claim at all, not null')
  assertEquals(
    'email_verified' in claims,
    false,
    'email_verified must go too -- false would assert something about an address that does not exist',
  )
})

Deno.test('an account with an email still emits both claims', () => {
  const claims = claimsForScopes(
    { email: 'u@example.test', emailVerified: true, updatedAt: new Date() },
    ['email'],
  )
  assertEquals(claims.email, 'u@example.test')
  assertEquals(claims.email_verified, true)
})

// makeTestDeps (tests/helpers.ts) wires the real createVerificationService
// deps shape -- the brief's standalone `verificationCtx()` omitted tokenRepo
// and sessionRepo and invented a {publicUrl, verificationTtl} config that
// does not match the real Config type, so this reuses the existing helper
// instead of hand-rolling a second one.
//
// Not `assertRejects(fn, AppError)`: AppError's constructor is private (the
// mass-assignment-safe `AppError.of` factory), so the class itself is not a
// public constructor type and the overload does not typecheck. Catch and
// narrow with `assert` instead, matching errors.test.ts's direct style.
async function rejects(fn: () => Promise<unknown>): Promise<AppError> {
  try {
    await fn()
  } catch (err) {
    assert(err instanceof AppError)
    return err
  }
  throw new Error('expected function to reject')
}

Deno.test('a guest cannot start an account deletion -- there is nowhere to send the link', async () => {
  const ctx = makeTestDeps()
  const guest = await ctx.userRepo.create(guestRow('guest_del'))
  const err = await rejects(() =>
    ctx.deps.verificationService.startAccountDeletion(guest.id)
  )
  assertEquals(err.code, 'account_has_no_email')
  assertEquals(ctx.sentEmails.length, 0, 'nothing may be sent')
})

Deno.test('a guest cannot start an email change -- there is no address to authorise from', async () => {
  const ctx = makeTestDeps()
  const guest = await ctx.userRepo.create(guestRow('guest_chg'))
  const err = await rejects(() =>
    ctx.deps.verificationService.startEmailChange(guest.id, 'new@example.test')
  )
  assertEquals(err.code, 'account_has_no_email')
  assertEquals(ctx.sentEmails.length, 0)
})
