import { assertEquals } from '@std/assert'
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
