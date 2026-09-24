import { assert, assertEquals, assertMatch, assertRejects } from '@std/assert'
import { makeTestDeps, TEST_TOTP_KEY, totpCode } from '../helpers.ts'
import { AppError } from '../../src/lib/errors.ts'
import { createInMemoryTotpRepository } from '../../src/modules/mfa/totp.repository.ts'
import { createTotpService } from '../../src/modules/mfa/totp.service.ts'

async function setup(env: Record<string, string> = {}) {
  const ctx = makeTestDeps(env)
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: `t-${crypto.randomUUID()}@b.com`,
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  return { ...ctx, totp: ctx.deps.totpService, user }
}

async function enrolled() {
  const ctx = await setup()
  const { secret } = await ctx.totp.startSetup(ctx.user.id)
  const { recovery_codes } = await ctx.totp.confirm(
    ctx.user.id,
    await totpCode(secret),
  )
  return { ...ctx, secret, recovery_codes }
}

const code = (p: Promise<unknown>) =>
  p.then(() => 'ok', (e) => (e instanceof AppError ? e.code : String(e)))

Deno.test('startSetup returns a base32 secret and a matching otpauth URI', async () => {
  const ctx = await setup()
  const { secret, otpauth_uri } = await ctx.totp.startSetup(ctx.user.id)
  assertMatch(secret, /^[A-Z2-7]{32}$/)
  const uri = new URL(otpauth_uri)
  assertEquals(uri.searchParams.get('secret'), secret)
  assertEquals(uri.searchParams.get('issuer'), 'test.local')
  assert(decodeURIComponent(uri.pathname).endsWith(`:${ctx.user.email}`))
  assertEquals(await ctx.totp.isEnabled(ctx.user.id), false)
})

Deno.test('the secret is stored sealed, never in the clear', async () => {
  const ctx = await setup()
  const { secret } = await ctx.totp.startSetup(ctx.user.id)
  const row = await ctx.totpRepo.find(ctx.user.id)
  assertMatch(row!.secret, /^v1:/)
  assert(!row!.secret.includes(secret))
})

Deno.test('startSetup again replaces a pending setup', async () => {
  const ctx = await setup()
  const first = await ctx.totp.startSetup(ctx.user.id)
  const second = await ctx.totp.startSetup(ctx.user.id)
  assert(first.secret !== second.secret)
  assertEquals(
    await code(ctx.totp.confirm(ctx.user.id, await totpCode(first.secret))),
    'totp_invalid_code',
  )
  await ctx.totp.confirm(ctx.user.id, await totpCode(second.secret))
  assert(await ctx.totp.isEnabled(ctx.user.id))
})

Deno.test('confirm turns TOTP on and returns ten recovery codes once', async () => {
  const ctx = await enrolled()
  assert(await ctx.totp.isEnabled(ctx.user.id))
  assertEquals(ctx.recovery_codes.length, 10)
})

Deno.test('startSetup while enabled is 409 and leaves the enabled secret alone', async () => {
  const ctx = await enrolled()
  const before = await ctx.totpRepo.find(ctx.user.id)
  assertEquals(
    await code(ctx.totp.startSetup(ctx.user.id)),
    'totp_already_enabled',
  )
  assertEquals(await ctx.totpRepo.find(ctx.user.id), before)
})

Deno.test('startSetup propagates a non-duplicate createPending failure as-is', async () => {
  const ctx = await setup()
  const totpRepo = {
    ...createInMemoryTotpRepository(),
    createPending() {
      return Promise.reject(new Error('db down'))
    },
  }
  const totp = createTotpService({
    totpRepo,
    userRepo: ctx.userRepo,
    issuer: 'http://test.local',
    encryptionKey: TEST_TOTP_KEY,
  })
  await assertRejects(
    () => totp.startSetup(ctx.user.id),
    Error,
    'db down',
  )
})

Deno.test('confirm with no setup is totp_not_pending; confirm twice is 409', async () => {
  const ctx = await setup()
  assertEquals(
    await code(ctx.totp.confirm(ctx.user.id, '123456')),
    'totp_not_pending',
  )
  const e = await enrolled()
  assertEquals(
    await code(e.totp.confirm(e.user.id, await totpCode(e.secret, 1))),
    'totp_already_enabled',
  )
})

Deno.test('confirm with a wrong code is totp_invalid_code and stays pending', async () => {
  const ctx = await setup()
  const { secret } = await ctx.totp.startSetup(ctx.user.id)
  const right = await totpCode(secret)
  const wrong = right === '000000' ? '111111' : '000000'
  assertEquals(
    await code(ctx.totp.confirm(ctx.user.id, wrong)),
    'totp_invalid_code',
  )
  assertEquals(await ctx.totp.isEnabled(ctx.user.id), false)
})

Deno.test('verify accepts the next code and refuses a replayed one', async () => {
  const ctx = await enrolled()
  // Offset 0 was spent by confirm: replay protection must refuse it.
  assertEquals(
    await ctx.totp.verify(ctx.user.id, await totpCode(ctx.secret)),
    false,
  )
  const next = await totpCode(ctx.secret, 1)
  assertEquals(await ctx.totp.verify(ctx.user.id, next), true)
  assertEquals(await ctx.totp.verify(ctx.user.id, next), false)
})

Deno.test('verify accepts each recovery code once, however it is typed', async () => {
  const ctx = await enrolled()
  const [rc] = ctx.recovery_codes
  const sloppy = ` ${rc.toLowerCase().replaceAll('-', ' ')} `
  assertEquals(await ctx.totp.verify(ctx.user.id, sloppy), true)
  assertEquals(await ctx.totp.verify(ctx.user.id, rc), false)
})

Deno.test('verify is false for a user without TOTP, and for a pending setup', async () => {
  const ctx = await setup()
  assertEquals(await ctx.totp.verify(ctx.user.id, '123456'), false)
  const { secret } = await ctx.totp.startSetup(ctx.user.id)
  assertEquals(
    await ctx.totp.verify(ctx.user.id, await totpCode(secret)),
    false,
  )
})

Deno.test('disable needs a valid proof, then removes everything', async () => {
  const ctx = await enrolled()
  assertEquals(
    await code(ctx.totp.disable(ctx.user.id, 'nope')),
    'invalid_credentials',
  )
  assert(await ctx.totp.isEnabled(ctx.user.id))
  await ctx.totp.disable(ctx.user.id, ctx.recovery_codes[0])
  assertEquals(await ctx.totp.isEnabled(ctx.user.id), false)
  assertEquals(await ctx.totpRepo.find(ctx.user.id), null)
  assertEquals(await ctx.totp.verify(ctx.user.id, ctx.recovery_codes[1]), false)
})

Deno.test('reset removes TOTP without a proof', async () => {
  const ctx = await enrolled()
  await ctx.totp.reset(ctx.user.id)
  assertEquals(await ctx.totp.isEnabled(ctx.user.id), false)
})

Deno.test('with no key every management call is totp_not_configured', async () => {
  const ctx = await setup({ TOTP_ENCRYPTION_KEY: '' })
  for (
    const p of [
      ctx.totp.startSetup(ctx.user.id),
      ctx.totp.confirm(ctx.user.id, '123456'),
      ctx.totp.disable(ctx.user.id, '123456'),
      ctx.totp.reset(ctx.user.id),
    ]
  ) assertEquals(await code(p), 'totp_not_configured')
})

Deno.test('startSetup for an unknown user id is user_not_found', async () => {
  const ctx = await setup()
  // Not assertRejects(fn, AppError): AppError's constructor is private (the
  // mass-assignment-safe AppError.of factory), so the class is not a public
  // constructor type and that overload does not typecheck -- same reasoning
  // as guest-accounts.test.ts. Reuse this file's own `code` helper instead.
  assertEquals(
    await code(ctx.totp.startSetup('no-such-user')),
    'user_not_found',
  )
})
