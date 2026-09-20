import { assert, assertEquals } from '@std/assert'
import {
  GOOGLE_ENV,
  GOOGLE_TOKEN_ENDPOINT as TOKEN_ENDPOINT,
  makeTestApp,
  seedDefaultService,
  stubGoogleToken,
} from '../helpers.ts'
import { hashPassword } from '../../src/lib/password.ts'

// GOOGLE_ENV, idToken and stubGoogleToken are imported from tests/helpers.ts
// above -- do not redefine them here.

async function guestWithToken(ctx: ReturnType<typeof makeTestApp>) {
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: null,
    username: `guest_${crypto.randomUUID().slice(0, 8)}`,
    passwordHash: await hashPassword('pw-secret'),
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const res = await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'password',
      username: user.username,
      password: 'pw-secret',
      audience,
    }),
  })
  const pair = await res.json()
  return { user, accessToken: pair.access_token as string }
}

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

Deno.test('a guest binds Google and keeps its id, gaining a verified email', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const { user, accessToken } = await guestWithToken(ctx)
  // Captured BEFORE the bind: the assertion at the end is that these survived
  // it. Comparing a post-bind read against another post-bind read would assert
  // nothing at all.
  const before = await ctx.userRepo.findById(user.id)
  const passwordHashBefore = before?.passwordHash
  const usernameBefore = before?.username

  const google = stubGoogleToken({
    sub: 'g-100',
    email: 'player@example.test',
    email_verified: true,
  })
  let res: Response
  try {
    res = await bind(ctx, accessToken)
  } finally {
    google.restore()
  }
  assertEquals(res.status, 200)
  assert(google.calls.some((u) => u.startsWith(TOKEN_ENDPOINT)))

  const after = await ctx.userRepo.findById(user.id)
  assertEquals(after?.id, user.id, 'the user id must not change')
  assertEquals(after?.email, 'player@example.test')
  assertEquals(after?.emailVerified, true)
  // The stored credential must still work afterwards, which means the bind
  // touched neither of these.
  assertEquals(
    after?.passwordHash,
    passwordHashBefore,
    'the bind must not touch passwordHash',
  )
  assertEquals(
    after?.username,
    usernameBefore,
    'the username survives the bind',
  )
})

Deno.test('the code exchange sends no redirect_uri -- a native server auth code was never issued against one', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const { accessToken } = await guestWithToken(ctx)
  const google = stubGoogleToken({
    sub: 'g-900',
    email: 'body@example.test',
    email_verified: true,
  })
  let res: Response
  try {
    res = await bind(ctx, accessToken, 'native-server-auth-code')
  } finally {
    google.restore()
  }
  assertEquals(res.status, 200)
  assertEquals(google.bodies.length, 1, 'exactly one exchange must be sent')
  const body = google.bodies[0]
  assertEquals(body.get('code'), 'native-server-auth-code')
  assertEquals(body.get('client_id'), GOOGLE_ENV.GOOGLE_CLIENT_ID)
  assertEquals(body.get('client_secret'), GOOGLE_ENV.GOOGLE_CLIENT_SECRET)
  assertEquals(body.get('grant_type'), 'authorization_code')
  assert(
    !body.has('redirect_uri'),
    'sending redirect_uri on a native server-auth-code exchange is the ' +
      'classic redirect_uri_mismatch against real Google -- it was never ' +
      'issued against one',
  )
})

// The value is configuration because only Google can say which one is right,
// and no stub can stand in for that -- so the point of these two is that a
// wrong answer is a config change rather than a code change and a deploy.
// GOOGLE_REDIRECT_URI stays set throughout: it belongs to the browser leg and
// must not leak into this exchange, which was the original Critical finding.
Deno.test('GOOGLE_BIND_REDIRECT_URI=postmessage sends the web/JS popup value', async () => {
  const ctx = makeTestApp({
    ...GOOGLE_ENV,
    GOOGLE_BIND_REDIRECT_URI: 'postmessage',
  })
  const { accessToken } = await guestWithToken(ctx)
  const google = stubGoogleToken({
    sub: 'g-901',
    email: 'pm@example.test',
    email_verified: true,
  })
  try {
    assertEquals((await bind(ctx, accessToken, 'web-popup-code')).status, 200)
  } finally {
    google.restore()
  }
  assertEquals(google.bodies[0].get('redirect_uri'), 'postmessage')
})

Deno.test('GOOGLE_BIND_REDIRECT_URI set to a URI sends that URI verbatim', async () => {
  const ctx = makeTestApp({
    ...GOOGLE_ENV,
    GOOGLE_BIND_REDIRECT_URI: 'https://app.example.test/oauth2/callback',
  })
  const { accessToken } = await guestWithToken(ctx)
  const google = stubGoogleToken({
    sub: 'g-902',
    email: 'uri@example.test',
    email_verified: true,
  })
  try {
    assertEquals((await bind(ctx, accessToken, 'redirect-code')).status, 200)
  } finally {
    google.restore()
  }
  assertEquals(
    google.bodies[0].get('redirect_uri'),
    'https://app.example.test/oauth2/callback',
    'sent verbatim -- Google matches the registered URI exactly',
  )
  assertEquals(
    google.bodies[0].get('redirect_uri') === GOOGLE_ENV.GOOGLE_REDIRECT_URI,
    false,
    "the browser leg's redirect URI must never be what this exchange sends",
  )
})

Deno.test('binding is idempotent for the same Google account', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const { accessToken } = await guestWithToken(ctx)
  const claims = {
    sub: 'g-200',
    email: 'p2@example.test',
    email_verified: true,
  }

  let first: Response, second: Response
  const google = stubGoogleToken(claims)
  try {
    first = await bind(ctx, accessToken)
    second = await bind(ctx, accessToken)
  } finally {
    google.restore()
  }
  assertEquals(first.status, 200)
  assertEquals(second.status, 200, 'a retry must not 409 against itself')
})

Deno.test('a Google account already linked to someone else is refused', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const other = await guestWithToken(ctx)
  const mine = await guestWithToken(ctx)
  const claims = {
    sub: 'g-300',
    email: 'taken@example.test',
    email_verified: true,
  }

  const google = stubGoogleToken(claims)
  let res: Response
  try {
    await bind(ctx, other.accessToken)
    res = await bind(ctx, mine.accessToken)
  } finally {
    google.restore()
  }
  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'social_account_already_linked')
})

Deno.test('a Google email that belongs to another account is refused', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const now = new Date()
  await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: 'owned@example.test',
    passwordHash: 'x',
    createdAt: now,
    updatedAt: now,
  })
  const { accessToken } = await guestWithToken(ctx)

  const google = stubGoogleToken({
    sub: 'g-400',
    email: 'owned@example.test',
    email_verified: true,
  })
  let res: Response
  try {
    res = await bind(ctx, accessToken)
  } finally {
    google.restore()
  }
  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'email_taken')
})

Deno.test('an unverified Google email is refused and nothing is linked', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const { user, accessToken } = await guestWithToken(ctx)

  const google = stubGoogleToken({
    sub: 'g-500',
    email: 'unverified@example.test',
    email_verified: false,
  })
  let res: Response
  try {
    res = await bind(ctx, accessToken)
  } finally {
    google.restore()
  }
  assertEquals(res.status, 403)
  assertEquals(
    (await ctx.userRepo.findById(user.id))?.email,
    null,
    'no address may be taken from an unverified profile',
  )
})

Deno.test('binding without a token is 401 and never calls Google', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const google = stubGoogleToken({
    sub: 'g-600',
    email: 'x@y.test',
    email_verified: true,
  })
  let res: Response
  try {
    res = await ctx.app.request('/users/me/social-links', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'google', code: 'c' }),
    })
  } finally {
    google.restore()
  }
  assertEquals(res.status, 401)
  assertEquals(
    google.calls.length,
    0,
    'an unauthenticated request must not redeem a code',
  )
})

Deno.test('a user who already has an email keeps it -- binding is not an email change', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: 'mine@example.test',
    emailVerified: true,
    passwordHash: await hashPassword('pw-secret'),
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const pair = await (await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'password',
      username: 'mine@example.test',
      password: 'pw-secret',
      audience,
    }),
  })).json()

  const google = stubGoogleToken({
    sub: 'g-700',
    email: 'google@example.test',
    email_verified: true,
  })
  let res: Response
  try {
    res = await bind(ctx, pair.access_token)
  } finally {
    google.restore()
  }
  assertEquals(res.status, 200)
  assertEquals(
    (await ctx.userRepo.findById(user.id))?.email,
    'mine@example.test',
    'binding must not become a backdoor email change -- that is the F6 shape',
  )
})

Deno.test('a failed email patch does not leave a dangling social link', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const { accessToken } = await guestWithToken(ctx)

  // Simulates the real failure mode: users.repository.drizzle.ts's update()
  // throws straight out of a duplicate-key insert instead of returning null
  // (it never reaches its own `return findById(id)`), for ANY failure of the
  // write -- a race on the address is the likely real-world cause, but the
  // invariant under test (the link must never survive a failed patch) does
  // not depend on which. The repo double is a plain object, so overriding one
  // method in place is enough; no new fake type is needed.
  const realUpdate = ctx.userRepo.update.bind(ctx.userRepo)
  ctx.userRepo.update = () => Promise.reject(new Error('simulated db failure'))

  const google = stubGoogleToken({
    sub: 'g-800',
    email: 'race@example.test',
    email_verified: true,
  })
  let res: Response
  try {
    res = await bind(ctx, accessToken)
  } finally {
    google.restore()
    ctx.userRepo.update = realUpdate
  }

  // The write failed, so the caller must see a failure -- not a silent 200
  // that quietly dropped the email (app.onError maps an unrecognised
  // exception to a generic 500, never a fabricated email_taken).
  assertEquals(res.status, 500)
  assertEquals(
    await ctx.socialRepo.findByProviderAccount('google', 'g-800'),
    null,
    'a failed email patch must not leave a dangling social link',
  )
})

Deno.test('a retry after a double failure reconciles the missing email instead of rubber-stamping success', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const { user, accessToken } = await guestWithToken(ctx)

  // The failure chain I1 describes: link() succeeds, the email patch throws,
  // and the compensating deleteAllForUser -- against the SAME outage, so not
  // an independent failure -- also fails. The link survives even though the
  // patch never landed: the account is now linked-but-emailless.
  const realUpdate = ctx.userRepo.update.bind(ctx.userRepo)
  const realDelete = ctx.socialRepo.deleteAllForUser.bind(ctx.socialRepo)
  ctx.userRepo.update = () => Promise.reject(new Error('simulated db outage'))
  ctx.socialRepo.deleteAllForUser = () =>
    Promise.reject(new Error('simulated db outage'))

  const claims = {
    sub: 'g-950',
    email: 'reconcile@example.test',
    email_verified: true,
  }
  let google = stubGoogleToken(claims)
  let first: Response
  try {
    first = await bind(ctx, accessToken)
  } finally {
    google.restore()
  }
  assertEquals(first.status, 500)

  ctx.userRepo.update = realUpdate
  ctx.socialRepo.deleteAllForUser = realDelete

  // Confirm the trap actually sprang: linked to Google, still no email. If
  // this assertion ever fails, the scenario below is not being exercised.
  assert(
    await ctx.socialRepo.findByProviderAccount('google', 'g-950'),
    'the link must have survived the double failure',
  )
  assertEquals((await ctx.userRepo.findById(user.id))?.email, null)

  // The outage clears; the client retries the exact same bind.
  google = stubGoogleToken(claims)
  let second: Response
  try {
    second = await bind(ctx, accessToken)
  } finally {
    google.restore()
  }
  assertEquals(
    second.status,
    200,
    'a retry must succeed once the outage clears',
  )
  const after = await ctx.userRepo.findById(user.id)
  assertEquals(
    after?.email,
    'reconcile@example.test',
    'the retry must reconcile the missing email, not rubber-stamp success ' +
      'the way an unconditional existing?.userId === userId return would',
  )
  assertEquals(after?.emailVerified, true)
})
