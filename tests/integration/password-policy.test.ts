import { assert, assertEquals } from '@std/assert'
import { authHeader, makeTestApp, seedDefaultService } from '../helpers.ts'

const COMMON = 'password123'

function register(
  app: ReturnType<typeof makeTestApp>['app'],
  body: Record<string, string>,
) {
  return app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

Deno.test('registration refuses a common password', async () => {
  const { app } = makeTestApp()
  const res = await register(app, { email: 'a@b.com', password: COMMON })
  assertEquals(res.status, 400)
  assertEquals((await res.json()).error.code, 'weak_password')
})

Deno.test('registration refuses a password over 72 bytes', async () => {
  const { app } = makeTestApp()
  const res = await register(app, {
    email: 'a@b.com',
    password: 'a'.repeat(73),
  })
  assertEquals(res.status, 400)
  assertEquals((await res.json()).error.code, 'password_too_long')
})

Deno.test('a self-service password change refuses a common password', async () => {
  const { app, orgRepo } = makeTestApp()
  const user = await (await register(app, {
    email: 'a@b.com',
    password: 'pw123456',
  })).json()
  const audience = await seedDefaultService(orgRepo, user.id)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'pw123456',
    audience,
  )

  const res = await app.request(`/users/${user.id}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', Authorization },
    body: JSON.stringify({ password: COMMON, current_password: 'pw123456' }),
  })
  assertEquals(res.status, 400)
  assertEquals((await res.json()).error.code, 'weak_password')

  // The old password still works: a refused change must change nothing.
  await authHeader(app, 'a@b.com', 'pw123456', audience)
})

// The check has to run BEFORE the reset token is consumed. Consuming first
// would burn the link on a weak password and strand the user -- the same bug
// PR #35 fixed on the email-change path.
Deno.test('a refused reset password leaves the link usable', async () => {
  const { app, sentEmails, orgRepo } = makeTestApp()
  const user = await (await register(app, {
    email: 'a@b.com',
    password: 'pw123456',
  })).json()
  const audience = await seedDefaultService(orgRepo, user.id)

  await app.request('/password-reset/request', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com' }),
  })
  const link = sentEmails.at(-1)!.link!
  const token = new URL(link).searchParams.get('token')!

  const submit = (password: string) =>
    app.request('/password-reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, password }),
    })

  const weak = await submit(COMMON)
  assertEquals(weak.status, 400)
  assertEquals((await weak.json()).error.code, 'weak_password')

  // Same link, acceptable password: still works, so the refusal cost nothing.
  assertEquals((await submit('a-fine-passphrase')).status, 204)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'a-fine-passphrase',
    audience,
  )
  assert(Authorization.startsWith('Bearer '))
})
