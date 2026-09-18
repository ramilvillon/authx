import { assert, assertEquals } from '@std/assert'
import {
  GOOGLE_ENV,
  keySet,
  makeTestApp,
  seedDefaultService,
  stubGoogleToken,
} from '../helpers.ts'
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
  // /users/me is documented as publicUserSchema and must actually be one: a
  // guest has no address (null, not ''), and its generated username is there.
  const body = await me.json()
  assertEquals(body.email, null)
  assertEquals(body.username, cred.username)
})

Deno.test('a malformed guest request does not spend the creation budget', async () => {
  const ctx = makeTestApp({ GUEST_RATE_LIMIT: '1' })
  await seedGuestService(ctx, true)

  // The limiter runs before the validator, so without countOnly this garbage
  // body would spend the one-request budget and lock out the next real
  // player.
  const bad = await ctx.app.request('/users/guest', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({}),
  })
  assertEquals(bad.status, 400)

  const good = await createGuest(ctx.app)
  assertEquals(
    good.status,
    201,
    'the malformed request must not have spent the budget',
  )
})

Deno.test('the guest creation budget still blocks once it is genuinely spent', async () => {
  const ctx = makeTestApp({ GUEST_RATE_LIMIT: '1' })
  await seedGuestService(ctx, true)
  assertEquals((await createGuest(ctx.app)).status, 201)
  assertEquals((await createGuest(ctx.app)).status, 429)
})

// Local copy, not imported from social-links.test.ts: importing one Deno test
// file from another evaluates it and re-registers its Deno.test calls, and
// this is eight lines -- not worth a cross-file dependency.
const bind = (
  ctx: ReturnType<typeof makeTestApp>,
  accessToken: string,
  code = 'server-auth-code',
) =>
  ctx.app.request('/users/me/social-links', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ provider: 'google', code }),
  })

Deno.test('the whole arc: play as a guest, bind Google, come back on a new device', async () => {
  const ctx = makeTestApp({ ...GOOGLE_ENV })
  const { audience } = await seedGuestService(ctx, true)

  // 1. First launch: no sign-up.
  const cred = await (await createGuest(ctx.app)).json()

  // 2. Relaunch: the stored credential still works. This is the call the
  //    client makes on every single launch.
  const first = await grant(ctx.app, {
    grant_type: 'password',
    username: cred.username,
    password: cred.password,
    audience,
  })
  assertEquals(first.status, 200)
  const { access_token } = await first.json()
  const me = await (await ctx.app.request('/users/me', {
    headers: { authorization: `Bearer ${access_token}` },
  })).json()
  const playerId = me.id

  // 3. Bind Google.
  const google = stubGoogleToken({
    sub: 'g-arc',
    email: 'arc@example.test',
    email_verified: true,
  })
  try {
    assertEquals((await bind(ctx, access_token)).status, 200)
  } finally {
    google.restore()
  }

  // 4. The old device keeps working, unchanged. The bind must not have
  //    touched passwordHash or the username.
  const after = await grant(ctx.app, {
    grant_type: 'password',
    username: cred.username,
    password: cred.password,
    audience,
  })
  assertEquals(after.status, 200, 'the stored credential must survive a bind')

  // 5. Same account throughout -- the entire point of the feature. Progress is
  //    keyed on this id.
  const meAfter = await (await ctx.app.request('/users/me', {
    headers: {
      authorization: `Bearer ${(await after.json()).access_token}`,
    },
  })).json()
  assertEquals(meAfter.id, playerId)

  // 6. The account now has a verified address, so the email-dependent flows
  //    that were unreachable for a guest have opened up.
  const row = await ctx.userRepo.findById(playerId)
  assertEquals(row?.email, 'arc@example.test')
  assertEquals(row?.emailVerified, true)
})

Deno.test('a guest cannot start an account deletion, but can once it has bound', async () => {
  const ctx = makeTestApp({ ...GOOGLE_ENV })
  const { audience } = await seedGuestService(ctx, true)
  const cred = await (await createGuest(ctx.app)).json()
  const { access_token } = await (await grant(ctx.app, {
    grant_type: 'password',
    username: cred.username,
    password: cred.password,
    audience,
  })).json()

  const me = await (await ctx.app.request('/users/me', {
    headers: { authorization: `Bearer ${access_token}` },
  })).json()

  // Self-service deletion is DELETE /users/:id on your own id: it does not
  // delete, it sends a confirmation link to the address on file (202
  // confirmation_sent). A guest has no address, so it cannot be authorised.
  const del = () =>
    ctx.app.request(`/users/${me.id}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${access_token}` },
    })

  const before = await del()
  assertEquals(before.status, 400)
  assertEquals((await before.json()).error.code, 'account_has_no_email')
  assertEquals(ctx.sentEmails.length, 0, 'nothing may be sent')

  const google = stubGoogleToken({
    sub: 'g-del',
    email: 'del@example.test',
    email_verified: true,
  })
  try {
    await bind(ctx, access_token)
  } finally {
    google.restore()
  }

  // After: there is an address, so the normal out-of-band flow works.
  const after = await del()
  assertEquals(after.status, 202)
  assertEquals((await after.json()).status, 'confirmation_sent')
  assertEquals(ctx.sentEmails.at(-1)?.to, 'del@example.test')
  assertEquals(ctx.sentEmails.at(-1)?.purpose, 'account_deletion')
})
