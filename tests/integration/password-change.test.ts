import { assertEquals } from '@std/assert'
import {
  authHeader,
  keySet,
  makeTestApp,
  seedDefaultService,
  seedPlatformAdmin,
} from '../helpers.ts'
import { signAccessToken } from '../../src/lib/jwt.ts'

const PASSWORD = 'pw123456'

async function registerAndId(
  app: ReturnType<typeof makeTestApp>['app'],
  email: string,
) {
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD }),
  })
  return (await res.json()).id as string
}

// Does this password still mint tokens? The only honest way to ask whether a
// change went through.
async function passwordStillWorks(
  app: ReturnType<typeof makeTestApp>['app'],
  email: string,
  password: string,
  audience: string,
) {
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'password',
      username: email,
      password,
      audience,
    }),
  })
  return res.status === 200
}

Deno.test('a self-service password change without current_password is refused', async () => {
  const { app, orgRepo } = makeTestApp()
  const id = await registerAndId(app, 'victim@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  // Stands in for a stolen access token: it is valid, but its holder never
  // proved they know the password.
  const { Authorization } = await authHeader(
    app,
    'victim@b.com',
    PASSWORD,
    audience,
  )

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'attacker-chosen-pw' }),
  })

  assertEquals(
    res.status,
    400,
    'a password change must prove the current password',
  )
  assertEquals(
    await passwordStillWorks(app, 'victim@b.com', PASSWORD, audience),
    true,
    'the original password must still be valid',
  )
  assertEquals(
    await passwordStillWorks(
      app,
      'victim@b.com',
      'attacker-chosen-pw',
      audience,
    ),
    false,
    'the attacker-chosen password must never have been set',
  )
})

Deno.test('a self-service password change with the wrong current_password is refused', async () => {
  const { app, orgRepo } = makeTestApp()
  const id = await registerAndId(app, 'victim2@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'victim2@b.com',
    PASSWORD,
    audience,
  )

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({
      password: 'attacker-chosen-pw',
      current_password: 'not-the-password',
    }),
  })

  assertEquals(
    res.status,
    401,
    'a guessed current_password must not be accepted',
  )
  assertEquals(
    await passwordStillWorks(app, 'victim2@b.com', PASSWORD, audience),
    true,
    'the original password must still be valid',
  )
})

Deno.test('a passwordless account cannot have a first password set through self-service', async () => {
  const { app, userRepo, orgRepo } = makeTestApp()
  const now = new Date()
  // What Google login creates: a real user with no password at all.
  const user = await userRepo.create({
    id: crypto.randomUUID(),
    email: 'google-user@b.com',
    passwordHash: null,
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(orgRepo, user.id)
  const Authorization = `Bearer ${await signAccessToken({
    sub: user.id,
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: audience,
    org: 'test',
    scope: '',
    clientId: 'cid_test',
    subType: 'user',
  })}`

  // There is no hash to prove against, so the legitimate owner's request and a
  // stolen token's request are byte-identical. Refuse both; an operator holding
  // users:update:any is the way in until a reset flow exists.
  const res = await app.request(`/users/${user.id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({
      password: 'attacker-chosen-pw',
      current_password: 'anything-at-all',
    }),
  })

  assertEquals(res.status, 401)
  assertEquals(
    await passwordStillWorks(
      app,
      'google-user@b.com',
      'attacker-chosen-pw',
      audience,
    ),
    false,
    'no password may be set on a passwordless account through self-service',
  )
})

Deno.test('an operator with users:update:any sets a password without proving the current one', async () => {
  const { app, orgRepo } = makeTestApp()
  const id = await registerAndId(app, 'locked-out@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  // An operator never knows the user's password — that is the whole point of
  // the permission, and it is the only way back in for a passwordless account.
  const Authorization = `Bearer ${await seedPlatformAdmin([
    'users:update:any',
  ])}`

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'operator-set-pw' }),
  })

  assertEquals(res.status, 200)
  assertEquals(
    await passwordStillWorks(
      app,
      'locked-out@b.com',
      'operator-set-pw',
      audience,
    ),
    true,
    'the operator-set password must work',
  )
  assertEquals(
    await passwordStillWorks(app, 'locked-out@b.com', PASSWORD, audience),
    false,
    'the old password must stop working',
  )
})

Deno.test('repeated failed password proofs are throttled', async () => {
  const { app, orgRepo } = makeTestApp()
  const id = await registerAndId(app, 'brute@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'brute@b.com',
    PASSWORD,
    audience,
  )

  const guess = (n: number) =>
    app.request(`/users/${id}`, {
      method: 'PATCH',
      headers: { Authorization, 'content-type': 'application/json' },
      body: JSON.stringify({
        password: 'attacker-chosen-pw',
        current_password: `guess-${n}`,
      }),
    })

  const statuses: number[] = []
  for (let n = 0; n < 8; n++) statuses.push((await guess(n)).status)

  assertEquals(
    statuses.includes(429),
    true,
    `guessing must start being refused; got ${statuses.join(',')}`,
  )
  assertEquals(
    await passwordStillWorks(app, 'brute@b.com', PASSWORD, audience),
    true,
    'the original password must survive the attempt',
  )
})

Deno.test("an unauthenticated flood does not consume a victim's password-change budget", async () => {
  const { app, orgRepo } = makeTestApp()
  const id = await registerAndId(app, 'target@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'target@b.com',
    PASSWORD,
    audience,
  )

  // This is what sank the first attempt at F11: a throttle registered before
  // requireAuth counts junk-token requests, so an attacker who cannot
  // authenticate at all can still exhaust the bucket and lock the real owner
  // out of changing their own password.
  for (let n = 0; n < 30; n++) {
    const junk = await app.request(`/users/${id}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer junk-token-${n}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ password: 'x'.repeat(12), current_password: 'y' }),
    })
    assertEquals(junk.status, 401, 'a junk token must not authenticate')
  }

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({
      password: 'my-new-password',
      current_password: PASSWORD,
    }),
  })

  assertEquals(
    res.status,
    200,
    'the owner must still be able to change their password',
  )
  assertEquals(
    await passwordStillWorks(app, 'target@b.com', 'my-new-password', audience),
    true,
  )
})
