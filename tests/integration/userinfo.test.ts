import { assert, assertEquals } from '@std/assert'
import { keySet, makeTestApp } from '../helpers.ts'
import { signAccessToken } from '../../src/lib/jwt.ts'

async function seedUser(ctx: ReturnType<typeof makeTestApp>) {
  await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
  const user = await ctx.userRepo.findByEmail('a@b.com')
  await ctx.userRepo.update(user!.id, { name: 'Ada L', emailVerified: true })
  return user!
}

function userToken(sub: string, oidcScope?: string) {
  return signAccessToken({
    sub,
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'acme-app',
    org: 'o',
    scope: '',
    clientId: 'cid_app',
    oidcScope,
  })
}

Deno.test('userinfo returns sub + scoped claims', async () => {
  const ctx = makeTestApp()
  const user = await seedUser(ctx)
  const token = await userToken(user.id, 'openid email profile')
  const res = await ctx.app.request('/oauth/userinfo', {
    headers: { authorization: `Bearer ${token}` },
  })
  assertEquals(res.status, 200)
  const body = await res.json()
  assertEquals(body.sub, user.id)
  assertEquals(body.email, 'a@b.com')
  assertEquals(body.email_verified, true)
  assertEquals(body.name, 'Ada L')
})

Deno.test('userinfo without a bearer token is 401 with WWW-Authenticate', async () => {
  const ctx = makeTestApp()
  const res = await ctx.app.request('/oauth/userinfo')
  assertEquals(res.status, 401)
  assert(res.headers.get('www-authenticate')?.startsWith('Bearer'))
})

Deno.test('userinfo rejects an M2M token (no user for sub) with 401', async () => {
  const ctx = makeTestApp()
  const token = await userToken('service-id-not-a-user', 'openid')
  const res = await ctx.app.request('/oauth/userinfo', {
    headers: { authorization: `Bearer ${token}` },
  })
  assertEquals(res.status, 401)
  assert(res.headers.get('www-authenticate')?.startsWith('Bearer'))
})
