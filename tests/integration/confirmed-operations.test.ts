import { assert, assertEquals } from '@std/assert'
import {
  authHeader,
  makeTestApp,
  seedDefaultService,
  seedPlatformAdmin,
} from '../helpers.ts'

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

const emailOf = async (
  app: ReturnType<typeof makeTestApp>['app'],
  Authorization: string,
) =>
  (await (await app.request('/users/me', { headers: { Authorization } }))
    .json()).email

Deno.test('a self-service email change is not applied until it is confirmed', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  // Pixel Quest holds this token legitimately; it never proved Dana asked.
  const { Authorization } = await authHeader(
    app,
    'dana@b.com',
    PASSWORD,
    audience,
  )

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'attacker@evil.test' }),
  })

  assertEquals(
    res.status,
    202,
    'the change is accepted for confirmation, not applied',
  )
  assertEquals(
    await emailOf(app, Authorization),
    'dana@b.com',
    'the address must not change before the owner confirms',
  )
  // The authorising link goes to the address the app does NOT control. Sending
  // it to the new address would let the attacker click their own link.
  assertEquals(sentEmails.at(-1)?.to, 'dana@b.com')
})

// Everything the browser would fetch when the owner clicks the mailed link.
const follow = (
  app: ReturnType<typeof makeTestApp>['app'],
  link: string,
) => app.request(new URL(link).pathname + new URL(link).search)

Deno.test('confirming the link applies the email change and leaves the new address unverified', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana2@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana2@b.com',
    PASSWORD,
    audience,
  )

  await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'dana-new@b.com' }),
  })
  const res = await follow(app, sentEmails.at(-1)!.link)

  assertEquals(res.status, 200)
  assertEquals(await emailOf(app, Authorization), 'dana-new@b.com')
  // Confirming from the OLD address proves the owner authorised the move; it
  // does not prove they control the new one. The existing verify-email flow
  // does that, so the new address starts unverified.
  assertEquals((await userRepo.findById(id))?.emailVerified, false)
})

Deno.test('a confirmation link is single-use', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana3@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana3@b.com',
    PASSWORD,
    audience,
  )

  await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'dana3-new@b.com' }),
  })
  const link = sentEmails.at(-1)!.link
  assertEquals((await follow(app, link)).status, 200)
  assertEquals((await follow(app, link)).status, 400, 'replay must be refused')
})

Deno.test('a self-service account deletion is not performed until it is confirmed', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana4@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana4@b.com',
    PASSWORD,
    audience,
  )

  const res = await app.request(`/users/${id}`, {
    method: 'DELETE',
    headers: { Authorization },
  })

  assertEquals(res.status, 202)
  assertEquals(
    !!(await userRepo.findById(id)),
    true,
    'the account must survive',
  )
  assertEquals(sentEmails.at(-1)?.to, 'dana4@b.com')
  assertEquals(sentEmails.at(-1)?.purpose, 'account_deletion')
})

Deno.test('confirming the link performs the account deletion', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana5@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana5@b.com',
    PASSWORD,
    audience,
  )

  await app.request(`/users/${id}`, {
    method: 'DELETE',
    headers: { Authorization },
  })
  const res = await follow(app, sentEmails.at(-1)!.link)

  assertEquals(res.status, 200)
  assertEquals(await userRepo.findById(id), null, 'the account must be gone')
})

Deno.test('a verify-email token cannot be redeemed at the confirm endpoint', async () => {
  const { app, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana6@b.com')
  await seedDefaultService(orgRepo, id)
  // Registration mails an ordinary verification link.
  await app.request('/verify-email/resend', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'dana6@b.com' }),
  })
  const verifyLink = sentEmails.at(-1)!.link
  assertEquals(sentEmails.at(-1)?.purpose, 'verify_email')

  // Same token, pointed at the confirmation endpoint. Purpose must gate it.
  const token = new URL(verifyLink).searchParams.get('token')
  assertEquals((await app.request(`/confirm?token=${token}`)).status, 400)
})

Deno.test('an operator changes an email and deletes an account with no confirmation step', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana7@b.com')
  await seedDefaultService(orgRepo, id)
  // users:update:any / users:delete:any are already bound to the platform
  // audience, so this path is not the one F6 is about.
  const Authorization = `Bearer ${await seedPlatformAdmin(userRepo, [
    'users:update:any',
    'users:delete:any',
  ])}`
  const before = sentEmails.length

  const patched = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'moved@b.com' }),
  })
  assertEquals(patched.status, 200)
  assertEquals((await userRepo.findById(id))?.email, 'moved@b.com')

  const deleted = await app.request(`/users/${id}`, {
    method: 'DELETE',
    headers: { Authorization },
  })
  assertEquals(deleted.status, 204)
  assertEquals(await userRepo.findById(id), null)
  assertEquals(
    sentEmails.length,
    before,
    'no confirmation mail on the operator path',
  )
})

Deno.test('a confirmed self-service deletion is soft, and recoverable until it is purged', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const id = await registerAndId(app, 'dana8@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'dana8@b.com',
    PASSWORD,
    audience,
  )

  await app.request(`/users/${id}`, {
    method: 'DELETE',
    headers: { Authorization },
  })
  assertEquals((await follow(app, sentEmails.at(-1)!.link)).status, 200)

  // Gone from every ordinary lookup...
  assertEquals(await userRepo.findById(id), null)
  // ...but this is the path an attacker can trigger, so it must land in the
  // grace period like any other deletion, not destroy the row outright.
  assertEquals(
    (await userRepo.findDeletedBefore(new Date(Date.now() + 1000))).length,
    1,
    'a confirmed deletion must be soft, not a hard delete that skips the cascade',
  )
})

// users.email is UNIQUE, and findAnyByEmail guarded only register() and the
// two Google paths. The email-change path wrote straight through, so against
// real MySQL the UPDATE raised a duplicate key AFTER the token had already
// been consumed -- and /confirm's bare catch rendered it as "invalid or
// expired". The owner lost a single-use link to an error that named the wrong
// cause. In-memory it was worse than an error: two rows held one address.
Deno.test('a self-service email change onto a taken address is refused up front', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  await registerAndId(app, 'victim@b.com')
  const moverId = await registerAndId(app, 'mover@b.com')
  const audience = await seedDefaultService(orgRepo, moverId)
  const { Authorization } = await authHeader(
    app,
    'mover@b.com',
    PASSWORD,
    audience,
  )
  const before = sentEmails.length

  const res = await app.request(`/users/${moverId}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'victim@b.com' }),
  })

  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'email_taken')
  assertEquals(
    sentEmails.length,
    before,
    'no confirmation link for a change that can never be applied',
  )
  assertEquals((await userRepo.findById(moverId))?.email, 'mover@b.com')
})

// The collation is case-insensitive, so this is the same address to the UNIQUE
// index even though it is not the same string to JavaScript.
Deno.test('a case-differing address counts as taken on an email change', async () => {
  const { app, orgRepo } = makeTestApp()
  await registerAndId(app, 'held@b.com')
  const moverId = await registerAndId(app, 'mover2@b.com')
  const audience = await seedDefaultService(orgRepo, moverId)
  const { Authorization } = await authHeader(
    app,
    'mover2@b.com',
    PASSWORD,
    audience,
  )

  const res = await app.request(`/users/${moverId}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'HELD@b.com' }),
  })
  assertEquals(res.status, 409)
})

// The operator path applies immediately with no confirmation step, so it needs
// its own guard -- it cannot inherit the one on the request leg.
Deno.test('an operator moving an email onto a taken address gets 409, not a driver error', async () => {
  const { app, userRepo, orgRepo } = makeTestApp()
  await registerAndId(app, 'taken8@b.com')
  const id = await registerAndId(app, 'dana8@b.com')
  await seedDefaultService(orgRepo, id)
  const Authorization = `Bearer ${await seedPlatformAdmin(userRepo, [
    'users:update:any',
  ])}`

  const res = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'taken8@b.com' }),
  })
  assertEquals(res.status, 409)
  assertEquals((await userRepo.findById(id))?.email, 'dana8@b.com')
})

// The address can be taken between requesting the change and confirming it.
// The re-check runs BEFORE the token is consumed, so the link survives a
// conflict it did not cause, and the page says which one it was.
Deno.test('an address taken after the link was sent fails the confirm without burning it', async () => {
  const { app, userRepo, orgRepo, sentEmails } = makeTestApp()
  const moverId = await registerAndId(app, 'mover3@b.com')
  const audience = await seedDefaultService(orgRepo, moverId)
  const { Authorization } = await authHeader(
    app,
    'mover3@b.com',
    PASSWORD,
    audience,
  )
  await app.request(`/users/${moverId}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'contested@b.com' }),
  })
  const link = sentEmails.at(-1)!.link
  // Someone else registers it in the meantime.
  const squatterId = await registerAndId(app, 'contested@b.com')

  const res = await follow(app, link)
  assertEquals(res.status, 409)
  assert((await res.text()).includes('already in use'))
  assertEquals((await userRepo.findById(moverId))?.email, 'mover3@b.com')

  // The link was not consumed: once the conflict is gone it still works.
  await userRepo.softDelete(squatterId)
  await userRepo.update(squatterId, { email: null })
  assertEquals((await follow(app, link)).status, 200)
  assertEquals((await userRepo.findById(moverId))?.email, 'contested@b.com')
})
