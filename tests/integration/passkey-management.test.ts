import { assertEquals } from '@std/assert'
import {
  authHeader,
  keySet,
  makeTestApp,
  PASSKEY_ENV,
  seedDefaultService,
} from '../helpers.ts'
import { signAccessToken } from '../../src/lib/jwt.ts'
import { createSoftAuthenticator } from '../soft-authenticator.ts'

async function setup(env: Record<string, string> = PASSKEY_ENV) {
  const ctx = makeTestApp(env)
  const email = `m-${crypto.randomUUID()}@b.com`
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'pw123456' }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const { Authorization } = await authHeader(
    ctx.app,
    email,
    'pw123456',
    audience,
  )
  const call = (method: string, path: string) =>
    ctx.app.request(path, { method, headers: { Authorization } })
  return { ...ctx, user, call }
}

async function enrol(
  ctx: Awaited<ReturnType<typeof setup>>,
  userId = ctx.user.id,
) {
  const auth = await createSoftAuthenticator()
  const o = await ctx.passkeyService.registrationOptions(userId, new Date())
  await ctx.passkeyService.register(userId, await auth.register(o))
}

Deno.test('list returns the passkeys without their keys', async () => {
  const ctx = await setup()
  await enrol(ctx)
  const res = await ctx.call('GET', '/users/me/passkeys')
  assertEquals(res.status, 200)
  const [p] = await res.json()
  assertEquals(Object.keys(p).sort(), [
    'aaguid',
    'backed_up',
    'created_at',
    'id',
    'last_used_at',
  ])
})

Deno.test("delete removes your own passkey, and 404s someone else's", async () => {
  const ctx = await setup()
  const other = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: `o-${crypto.randomUUID()}@b.com`,
    passwordHash: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  })
  await enrol(ctx, other.id)
  const [theirs] = await ctx.passkeyRepo.listForUser(other.id)
  assertEquals(
    (await ctx.call('DELETE', `/users/me/passkeys/${theirs.id}`)).status,
    404,
  )
  assertEquals((await ctx.passkeyRepo.listForUser(other.id)).length, 1)
  await enrol(ctx)
  const [mine] = await ctx.passkeyRepo.listForUser(ctx.user.id)
  assertEquals(
    (await ctx.call('DELETE', `/users/me/passkeys/${mine.id}`)).status,
    204,
  )
  assertEquals(await ctx.passkeyRepo.listForUser(ctx.user.id), [])
})

Deno.test('no token is 401; a service token is 404; passkeys off is 404', async () => {
  const ctx = await setup()
  assertEquals((await ctx.app.request('/users/me/passkeys')).status, 401)
  const service = `Bearer ${await signAccessToken({
    sub: 'some-app-service-id',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'platform',
    org: 'platform',
    scope: '',
    clientId: 'cid_m2m',
    subType: 'service',
  })}`
  assertEquals(
    (await ctx.app.request('/users/me/passkeys', {
      headers: { Authorization: service },
    })).status,
    404,
  )
  const off = await setup({})
  assertEquals((await off.call('GET', '/users/me/passkeys')).status, 404)
})
