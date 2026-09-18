import { assert, assertEquals } from '@std/assert'
import { keySet, makeTestApp, seedDefaultService } from '../helpers.ts'
import { hashPassword } from '../../src/lib/password.ts'
import { verifyAccessToken } from '../../src/lib/jwt.ts'

async function seedGuestRow(
  ctx: ReturnType<typeof makeTestApp>,
  username: string,
  password: string,
) {
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: null,
    username,
    passwordHash: await hashPassword(password),
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  return { user, audience }
}

const grant = (app: ReturnType<typeof makeTestApp>['app'], body: unknown) =>
  app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

Deno.test('a username and password exchange for a token', async () => {
  const ctx = makeTestApp()
  const { user, audience } = await seedGuestRow(
    ctx,
    'guest_abc123',
    'pw-secret',
  )
  const res = await grant(ctx.app, {
    grant_type: 'password',
    username: 'guest_abc123',
    password: 'pw-secret',
    audience,
  })
  assertEquals(res.status, 200)
  const pair = await res.json()
  const claims = await verifyAccessToken(pair.access_token, keySet.publicKeyPem)
  assertEquals(claims.sub, user.id)
})

Deno.test('a wrong password against a real username is still 401', async () => {
  const ctx = makeTestApp()
  const { audience } = await seedGuestRow(ctx, 'guest_wrong', 'pw-secret')
  const res = await grant(ctx.app, {
    grant_type: 'password',
    username: 'guest_wrong',
    password: 'not-it',
    audience,
  })
  assertEquals(res.status, 401)
})

Deno.test('an unknown username is 401, not 400 -- the schema must not reject it', async () => {
  const ctx = makeTestApp()
  const { audience } = await seedGuestRow(ctx, 'guest_real', 'pw-secret')
  const res = await grant(ctx.app, {
    grant_type: 'password',
    username: 'guest_nobody',
    password: 'pw-secret',
    audience,
  })
  assertEquals(
    res.status,
    401,
    'a 400 here means the zod schema still demands an email',
  )
})

Deno.test('email login is unchanged', async () => {
  const ctx = makeTestApp()
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: 'u@example.test',
    passwordHash: await hashPassword('pw-secret'),
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const res = await grant(ctx.app, {
    grant_type: 'password',
    username: 'u@example.test',
    password: 'pw-secret',
    audience,
  })
  assertEquals(res.status, 200)
})

async function seedGuestService(
  ctx: ReturnType<typeof makeTestApp>,
  guestsEnabled: boolean,
) {
  const now = new Date()
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: 'game',
    name: 'Game',
    createdAt: now,
  })
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: 'cid_game',
    clientSecretHash: null,
    name: 'Game',
    slug: 'game',
    audience: 'game-app',
    type: 'public',
    redirectUris: [],
    guestsEnabled,
    createdAt: now,
  })
  return { org, audience: 'game-app' }
}

const createGuest = (
  app: ReturnType<typeof makeTestApp>['app'],
  clientId = 'cid_game',
) =>
  app.request('/users/guest', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_id: clientId }),
  })

Deno.test('a guest is created and its credential immediately gets a token', async () => {
  const ctx = makeTestApp()
  const { audience } = await seedGuestService(ctx, true)

  const res = await createGuest(ctx.app)
  assertEquals(res.status, 201)
  const cred = await res.json()
  assert(cred.username.startsWith('guest_'), 'username is namespaced')
  assertEquals(cred.username.includes('@'), false, 'never shadows an email')
  assert(cred.password.length >= 32, 'password is a real secret')

  // The point of the feature: the credential works straight away. This fails
  // if the guest was not added to the service's org, because
  // issueTokensForService refuses a non-member.
  const token = await grant(ctx.app, {
    grant_type: 'password',
    username: cred.username,
    password: cred.password,
    audience,
  })
  assertEquals(token.status, 200, 'a guest must be a member of the service org')
})

Deno.test('two guests get different credentials', async () => {
  const ctx = makeTestApp()
  await seedGuestService(ctx, true)
  const a = await (await createGuest(ctx.app)).json()
  const b = await (await createGuest(ctx.app)).json()
  assert(a.username !== b.username)
  assert(a.password !== b.password)
})

Deno.test('a service that has not opted in refuses', async () => {
  const ctx = makeTestApp()
  await seedGuestService(ctx, false)
  const res = await createGuest(ctx.app)
  assertEquals(res.status, 404)
  assertEquals((await res.json()).error.code, 'guest_accounts_disabled')
})

Deno.test('an unknown client_id refuses', async () => {
  const ctx = makeTestApp()
  await seedGuestService(ctx, true)
  const res = await createGuest(ctx.app, 'cid_nope')
  assertEquals(res.status, 404)
})

Deno.test('a guest has no email and reports none', async () => {
  const ctx = makeTestApp()
  const { audience } = await seedGuestService(ctx, true)
  const cred = await (await createGuest(ctx.app)).json()
  const pair = await (await grant(ctx.app, {
    grant_type: 'password',
    username: cred.username,
    password: cred.password,
    audience,
  })).json()
  const me = await ctx.app.request('/users/me', {
    headers: { authorization: `Bearer ${pair.access_token}` },
  })
  assertEquals(me.status, 200)
  assertEquals((await me.json()).email, '')
})
