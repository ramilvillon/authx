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
