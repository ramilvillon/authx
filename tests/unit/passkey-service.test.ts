import { assert, assertEquals } from '@std/assert'
import { makeTestDeps, PASSKEY_ENV } from '../helpers.ts'
import { AppError } from '../../src/lib/errors.ts'
import { createSoftAuthenticator } from '../soft-authenticator.ts'
import { MAX_PASSKEYS } from '../../src/modules/passkeys/passkey.service.ts'
import { hashToken } from '../../src/lib/tokens.ts'

const code = (p: Promise<unknown>) =>
  p.then(() => 'ok', (e) => (e instanceof AppError ? e.code : String(e)))

async function setup(env: Record<string, string> = PASSKEY_ENV) {
  const ctx = makeTestDeps(env)
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: `p-${crypto.randomUUID()}@b.com`,
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  return { ...ctx, svc: ctx.deps.passkeyService, user }
}

async function enrolled(authOpts = {}) {
  const ctx = await setup()
  const auth = await createSoftAuthenticator(authOpts)
  const options = await ctx.svc.registrationOptions(ctx.user.id, new Date())
  await ctx.svc.register(ctx.user.id, await auth.register(options))
  return { ...ctx, auth }
}

Deno.test('a registered passkey signs in as its user', async () => {
  const ctx = await enrolled()
  const [row] = await ctx.passkeyRepo.listForUser(ctx.user.id)
  assertEquals(row.lastUsedAt, null)
  const options = await ctx.svc.signInOptions()
  assertEquals(options.allowCredentials ?? [], [])
  assertEquals(options.userVerification, 'required')
  assertEquals(
    await ctx.svc.verifySignIn(await ctx.auth.authenticate(options)),
    ctx.user.id,
  )
  assert((await ctx.passkeyRepo.listForUser(ctx.user.id))[0].lastUsedAt)
})

Deno.test('a sign-in response cannot be replayed', async () => {
  const ctx = await enrolled()
  const response = await ctx.auth.authenticate(await ctx.svc.signInOptions())
  assertEquals(await code(ctx.svc.verifySignIn(response)), 'ok')
  assertEquals(await code(ctx.svc.verifySignIn(response)), 'passkey_invalid')
})

Deno.test('an expired challenge is refused', async () => {
  const ctx = await enrolled()
  const challenge = 'ZXhwaXJlZC1jaGFsbGVuZ2U'
  await ctx.passkeyRepo.createChallenge({
    challengeHash: await hashToken(challenge),
    purpose: 'authenticate',
    userId: null,
    expiresAt: new Date(Date.now() - 1000),
  })
  assertEquals(
    await code(
      ctx.svc.verifySignIn(await ctx.auth.authenticate({ challenge })),
    ),
    'passkey_invalid',
  )
})

Deno.test('a register challenge cannot sign in, and cannot register another user', async () => {
  const ctx = await enrolled()
  const reg = await ctx.svc.registrationOptions(ctx.user.id, new Date())
  assertEquals(
    await code(ctx.svc.verifySignIn(await ctx.auth.authenticate(reg))),
    'passkey_invalid',
  )
  const other = await createSoftAuthenticator()
  const reg2 = await ctx.svc.registrationOptions(ctx.user.id, new Date())
  const intruder = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: `i-${crypto.randomUUID()}@b.com`,
    passwordHash: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  })
  assertEquals(
    await code(ctx.svc.register(intruder.id, await other.register(reg2))),
    'passkey_invalid',
  )
})

Deno.test('a response for another origin or RP id is refused', async () => {
  for (
    const opts of [{ origin: 'http://evil.local' }, { rpId: 'evil.local' }]
  ) {
    const ctx = await setup()
    const bad = await createSoftAuthenticator(opts)
    const options = await ctx.svc.registrationOptions(ctx.user.id, new Date())
    assertEquals(
      await code(ctx.svc.register(ctx.user.id, await bad.register(options))),
      'passkey_invalid',
    )
  }
})

Deno.test('user verification is required for both ceremonies', async () => {
  const ctx = await setup()
  const noUv = await createSoftAuthenticator({ userVerified: false })
  const options = await ctx.svc.registrationOptions(ctx.user.id, new Date())
  assertEquals(
    await code(ctx.svc.register(ctx.user.id, await noUv.register(options))),
    'passkey_invalid',
  )
})

Deno.test('an unknown credential and garbage both come back as passkey_invalid', async () => {
  const ctx = await setup()
  const stranger = await createSoftAuthenticator()
  const options = await ctx.svc.signInOptions()
  for (
    const response of [await stranger.authenticate(options), {}, null, 'x']
  ) {
    assertEquals(await code(ctx.svc.verifySignIn(response)), 'passkey_invalid')
  }
})

Deno.test('a counting authenticator whose counter goes backwards is refused', async () => {
  const ctx = await enrolled({ countsUses: true })
  await ctx.svc.verifySignIn(
    await ctx.auth.authenticate(await ctx.svc.signInOptions()),
  )
  ctx.auth.state.counter = 0 // a clone replaying an older state
  assertEquals(
    await code(
      ctx.svc.verifySignIn(
        await ctx.auth.authenticate(await ctx.svc.signInOptions()),
      ),
    ),
    'passkey_invalid',
  )
})

Deno.test('enrolment needs a sign-in in the last 5 minutes', async () => {
  const ctx = await setup()
  assertEquals(
    await code(
      ctx.svc.registrationOptions(
        ctx.user.id,
        new Date(Date.now() - 6 * 60_000),
      ),
    ),
    'fresh_login_required',
  )
})

Deno.test(`enrolment stops at ${MAX_PASSKEYS} passkeys`, async () => {
  const ctx = await setup()
  for (let i = 0; i < MAX_PASSKEYS; i++) {
    await ctx.passkeyRepo.create({
      id: crypto.randomUUID(),
      userId: ctx.user.id,
      credentialId: `c${i}`,
      credentialIdHash: await hashToken(`c${i}`),
      publicKey: 'cGs',
      counter: 0,
      transports: [],
      aaguid: '00000000-0000-0000-0000-000000000000',
      backedUp: false,
      createdAt: new Date(),
      lastUsedAt: null,
    })
  }
  assertEquals(
    await code(ctx.svc.registrationOptions(ctx.user.id, new Date())),
    'passkey_limit_reached',
  )
})

Deno.test('registering the same passkey twice is passkey_already_registered', async () => {
  const ctx = await enrolled()
  const options = await ctx.svc.registrationOptions(ctx.user.id, new Date())
  assertEquals(
    await code(ctx.svc.register(ctx.user.id, await ctx.auth.register(options))),
    'passkey_already_registered',
  )
})

Deno.test('list hides the public key; remove is owner-only', async () => {
  const ctx = await enrolled()
  const [p] = await ctx.svc.list(ctx.user.id)
  assertEquals(Object.keys(p).sort(), [
    'aaguid',
    'backed_up',
    'created_at',
    'id',
    'last_used_at',
  ])
  assertEquals(
    await code(ctx.svc.remove('someone-else', p.id)),
    'passkey_not_found',
  )
  assertEquals(await code(ctx.svc.remove(ctx.user.id, p.id)), 'ok')
  assertEquals(await ctx.svc.list(ctx.user.id), [])
})

Deno.test('with WEBAUTHN_RP_ID unset every method is passkey_not_configured', async () => {
  const ctx = await setup({})
  assertEquals(ctx.svc.enabled, false)
  assertEquals(await code(ctx.svc.signInOptions()), 'passkey_not_configured')
  assertEquals(
    await code(ctx.svc.registrationOptions(ctx.user.id, new Date())),
    'passkey_not_configured',
  )
  assertEquals(await code(ctx.svc.list(ctx.user.id)), 'passkey_not_configured')
})
