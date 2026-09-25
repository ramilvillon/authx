import { assert, assertEquals } from '@std/assert'
import {
  authHeader,
  makeTestApp,
  PASSKEY_ENV,
  seedDefaultService,
} from '../helpers.ts'
import { createSoftAuthenticator } from '../soft-authenticator.ts'

const PASSWORD = 'pw123456'
const NEW_PASSWORD = 'brand-new-pw-9'

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

const requestReset = (
  app: ReturnType<typeof makeTestApp>['app'],
  email: string,
) =>
  app.request('/password-reset/request', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  })

const submitReset = (
  app: ReturnType<typeof makeTestApp>['app'],
  token: string,
  password: string,
) =>
  app.request('/password-reset', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token, password }),
  })

const tokenFrom = (link: string) => new URL(link).searchParams.get('token')!

const canLogIn = async (
  app: ReturnType<typeof makeTestApp>['app'],
  email: string,
  password: string,
  audience: string,
) => {
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

Deno.test('a reset link replaces the password and the old one stops working', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana@b.com')
  const audience = await seedDefaultService(orgRepo, id)

  assertEquals((await requestReset(app, 'dana@b.com')).status, 204)
  assertEquals(sentEmails.at(-1)?.purpose, 'password_reset')
  assertEquals(sentEmails.at(-1)?.to, 'dana@b.com')

  const res = await submitReset(
    app,
    tokenFrom(sentEmails.at(-1)!.link),
    NEW_PASSWORD,
  )

  assertEquals(res.status, 204)
  assertEquals(await canLogIn(app, 'dana@b.com', NEW_PASSWORD, audience), true)
  assertEquals(await canLogIn(app, 'dana@b.com', PASSWORD, audience), false)
})

Deno.test('requesting a reset for an unknown address is silent and identical', async () => {
  const { app, sentEmails } = makeTestApp()
  const before = sentEmails.length

  // Same status, same shape, nothing sent: the response must not reveal whether
  // the address is registered.
  assertEquals((await requestReset(app, 'nobody@b.com')).status, 204)
  assertEquals(sentEmails.length, before)
})

Deno.test('a reset revokes every existing session and refresh token', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana2@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { refresh } = await authHeader(app, 'dana2@b.com', PASSWORD, audience)

  await requestReset(app, 'dana2@b.com')
  await submitReset(app, tokenFrom(sentEmails.at(-1)!.link), NEW_PASSWORD)

  // Reset is what someone reaches for BECAUSE they think they are compromised.
  // Leaving the attacker's credentials alive would defeat the point.
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: refresh,
    }),
  })
  assert(
    res.status >= 400,
    'refresh tokens minted before the reset must be dead',
  )
})

Deno.test('a reset deletes every passkey on the account', async () => {
  const { app, orgRepo, passkeyRepo, passkeyService, sentEmails } = makeTestApp(
    PASSKEY_ENV,
  )
  const id = await registerAndId(app, 'dana6@b.com')
  await seedDefaultService(orgRepo, id)
  const auth = await createSoftAuthenticator()
  const options = await passkeyService.registrationOptions(id, new Date())
  await passkeyService.register(id, await auth.register(options))
  assertEquals((await passkeyRepo.listForUser(id)).length, 1)

  await requestReset(app, 'dana6@b.com')
  const res = await submitReset(
    app,
    tokenFrom(sentEmails.at(-1)!.link),
    NEW_PASSWORD,
  )

  assertEquals(res.status, 204)
  assertEquals((await passkeyRepo.listForUser(id)).length, 0)
})

Deno.test('a reset verifies the address, since clicking the link proves control of it', async () => {
  const { app, userRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana3@b.com')
  // register leaves it unset rather than false, so assert falsy, not `false`.
  assert(!(await userRepo.findById(id))?.emailVerified)

  await requestReset(app, 'dana3@b.com')
  await submitReset(app, tokenFrom(sentEmails.at(-1)!.link), NEW_PASSWORD)

  assertEquals((await userRepo.findById(id))?.emailVerified, true)
})

Deno.test('a Google-created account with no password can reset its way to one', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const now = new Date()
  // Exactly what loginWithGoogle creates: passwordHash null, unverified.
  const user = await userRepo.create({
    id: crypto.randomUUID(),
    email: 'google-user@b.com',
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(orgRepo, user.id)

  await requestReset(app, 'google-user@b.com')
  const res = await submitReset(
    app,
    tokenFrom(sentEmails.at(-1)!.link),
    NEW_PASSWORD,
  )

  // F11 refuses a first-password-set through PATCH because a bearer token
  // proves nothing. An emailed link proves control of the address, which is the
  // same proof F6 accepts for deleting the account outright -- so it is good
  // enough to add a password to it. This is the hole F11 left, closed.
  assertEquals(res.status, 204)
  assertEquals(
    await canLogIn(app, 'google-user@b.com', NEW_PASSWORD, audience),
    true,
  )
})

Deno.test('a reset link is single-use', async () => {
  const { app, sentEmails } = makeTestApp()
  await registerAndId(app, 'dana4@b.com')
  await requestReset(app, 'dana4@b.com')
  const token = tokenFrom(sentEmails.at(-1)!.link)

  assertEquals((await submitReset(app, token, NEW_PASSWORD)).status, 204)
  assertEquals((await submitReset(app, token, 'another-pw-1')).status, 400)
})

Deno.test('a reset token is refused at the confirm endpoint', async () => {
  const { app, sentEmails } = makeTestApp()
  await registerAndId(app, 'dana5@b.com')
  await requestReset(app, 'dana5@b.com')
  const token = tokenFrom(sentEmails.at(-1)!.link)

  // Purpose confusion: /confirm acts immediately, so accepting a reset token
  // there would burn it without setting any password.
  assertEquals((await app.request(`/confirm?token=${token}`)).status, 400)
  // ...and it must still work at its own endpoint afterwards.
  assertEquals((await submitReset(app, token, NEW_PASSWORD)).status, 204)
})

// Someone who had the mailbox (or a stolen token) could mint these links, keep
// them, and use them after the owner recovers. Recovery exists to lock that
// person out, so every account-changing link minted before it must die with it.
Deno.test('a reset kills every other outstanding reset, email-change and deletion link', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana6@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana6@b.com',
    PASSWORD,
    audience,
  )

  await requestReset(app, 'dana6@b.com')
  const staleReset = tokenFrom(sentEmails.at(-1)!.link)
  await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'attacker@evil.test' }),
  })
  const staleEmailChange = tokenFrom(sentEmails.at(-1)!.link)
  await app.request(`/users/${id}`, {
    method: 'DELETE',
    headers: { Authorization },
  })
  const staleDeletion = tokenFrom(sentEmails.at(-1)!.link)
  assertEquals(sentEmails.at(-1)?.purpose, 'account_deletion')

  // The owner recovers with a fresh link.
  await requestReset(app, 'dana6@b.com')
  assertEquals(
    (await submitReset(app, tokenFrom(sentEmails.at(-1)!.link), NEW_PASSWORD))
      .status,
    204,
  )

  assertEquals(
    (await submitReset(app, staleReset, 'attacker-pw-1')).status,
    400,
  )
  assertEquals(
    (await app.request(`/confirm?token=${staleEmailChange}`)).status,
    400,
  )
  assertEquals(
    (await app.request(`/confirm?token=${staleDeletion}`)).status,
    400,
  )
  assertEquals(await canLogIn(app, 'dana6@b.com', NEW_PASSWORD, audience), true)
})

Deno.test('a password change kills an outstanding reset link', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana7@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana7@b.com',
    PASSWORD,
    audience,
  )
  await requestReset(app, 'dana7@b.com')
  const staleReset = tokenFrom(sentEmails.at(-1)!.link)

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({
      password: NEW_PASSWORD,
      current_password: PASSWORD,
    }),
  })
  assertEquals(res.status, 200)

  assertEquals(
    (await submitReset(app, staleReset, 'attacker-pw-1')).status,
    400,
  )
  assertEquals(await canLogIn(app, 'dana7@b.com', NEW_PASSWORD, audience), true)
})
