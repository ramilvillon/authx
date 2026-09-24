import { assertEquals } from '@std/assert'
import {
  authHeader,
  keySet,
  makeTestApp,
  PLATFORM_PERMISSIONS,
  seedDefaultService,
  seedPlatformAdmin,
  totpCode,
} from '../helpers.ts'
import { signAccessToken } from '../../src/lib/jwt.ts'

const PASSWORD = 'pw123456'

async function setup(env: Record<string, string> = {}) {
  const ctx = makeTestApp(env)
  const email = `m-${crypto.randomUUID()}@b.com`
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const { Authorization } = await authHeader(ctx.app, email, PASSWORD, audience)
  const call = (method: string, path: string, body?: unknown) =>
    ctx.app.request(path, {
      method,
      headers: { Authorization, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  return { ...ctx, user, email, audience, call }
}

async function enroll(ctx: Awaited<ReturnType<typeof setup>>) {
  const start = await ctx.call('POST', '/users/me/totp')
  assertEquals(start.status, 200)
  const { secret } = await start.json()
  const confirm = await ctx.call('POST', '/users/me/totp/confirm', {
    code: await totpCode(secret),
  })
  assertEquals(confirm.status, 200)
  // Both bodies carry secrets (the seed, the recovery codes): never cached.
  for (const res of [start, confirm]) {
    assertEquals(res.headers.get('cache-control'), 'no-store')
    assertEquals(res.headers.get('pragma'), 'no-cache')
  }
  const { recovery_codes } = await confirm.json()
  return { secret, recovery_codes: recovery_codes as string[] }
}

Deno.test('setup -> confirm -> disable over HTTP', async () => {
  const ctx = await setup()
  const { secret, recovery_codes } = await enroll(ctx)
  assertEquals(recovery_codes.length, 10)
  assertEquals((await ctx.call('POST', '/users/me/totp')).status, 409)
  const off = await ctx.call('DELETE', '/users/me/totp', {
    code: await totpCode(secret, 1),
  })
  assertEquals(off.status, 204)
  assertEquals((await ctx.call('POST', '/users/me/totp')).status, 200)
})

Deno.test('confirm with a wrong code is 400; without a setup it is 404', async () => {
  const ctx = await setup()
  assertEquals(
    (await ctx.call('POST', '/users/me/totp/confirm', { code: '123456' }))
      .status,
    404,
  )
  await ctx.call('POST', '/users/me/totp')
  const res = await ctx.call('POST', '/users/me/totp/confirm', { code: 'abc' })
  assertEquals(res.status, 400)
  assertEquals((await res.json()).error.code, 'totp_invalid_code')
})

Deno.test('disable takes a recovery code too, and refuses a wrong proof with 401', async () => {
  const ctx = await setup()
  const { recovery_codes } = await enroll(ctx)
  const bad = await ctx.call('DELETE', '/users/me/totp', {
    recovery_code: 'AAAA-AAAA-AAAA-AAAA',
  })
  assertEquals(bad.status, 401)
  const ok = await ctx.call('DELETE', '/users/me/totp', {
    recovery_code: recovery_codes[0],
  })
  assertEquals(ok.status, 204)
})

Deno.test('disable needs exactly one of code and recovery_code', async () => {
  const ctx = await setup()
  await enroll(ctx)
  assertEquals((await ctx.call('DELETE', '/users/me/totp', {})).status, 400)
  assertEquals(
    (await ctx.call('DELETE', '/users/me/totp', {
      code: '1',
      recovery_code: '2',
    })).status,
    400,
  )
})

Deno.test('wrong disable proofs are throttled per user', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const statuses = []
  for (let i = 0; i < 6; i++) {
    statuses.push(
      (await ctx.call('DELETE', '/users/me/totp', {
        recovery_code: 'AAAA-AAAA-AAAA-AAAA',
      })).status,
    )
  }
  assertEquals(statuses.slice(0, 5), [401, 401, 401, 401, 401])
  assertEquals(statuses[5], 429)
})

Deno.test('self-service routes are 404 when TOTP_ENCRYPTION_KEY is unset; operator reset still works', async () => {
  const ctx = await setup({ TOTP_ENCRYPTION_KEY: '' })
  const admin = await seedPlatformAdmin(ctx.userRepo, [
    ...PLATFORM_PERMISSIONS,
    'users:update:any',
  ])
  assertEquals(
    (await ctx.app.request(`/users/${ctx.user.id}/totp`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${admin}` },
    })).status,
    204,
  )
  assertEquals((await ctx.call('POST', '/users/me/totp')).status, 404)
  assertEquals(
    (await ctx.call('POST', '/users/me/totp/confirm', { code: '123456' }))
      .status,
    404,
  )
  assertEquals(
    (await ctx.call('DELETE', '/users/me/totp', { code: '123456' })).status,
    404,
  )
})

Deno.test('the routes need a bearer token', async () => {
  const ctx = makeTestApp()
  assertEquals(
    (await ctx.app.request('/users/me/totp', { method: 'POST' })).status,
    401,
  )
})

Deno.test('admin reset needs users:update:any on a platform token', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const narrow = await seedPlatformAdmin(ctx.userRepo, ['users:list'])
  const denied = await ctx.app.request(`/users/${ctx.user.id}/totp`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${narrow}` },
  })
  assertEquals(denied.status, 403)
  const admin = await seedPlatformAdmin(ctx.userRepo, [
    ...PLATFORM_PERMISSIONS,
    'users:update:any',
  ])
  const ok = await ctx.app.request(`/users/${ctx.user.id}/totp`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${admin}` },
  })
  assertEquals(ok.status, 204)
  assertEquals((await ctx.call('POST', '/users/me/totp')).status, 200)
})

Deno.test('a service token gets 404 from the /users/me/totp routes', async () => {
  const { app } = makeTestApp()
  const Authorization = `Bearer ${await signAccessToken({
    sub: 'some-app-service-id',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'platform',
    org: 'platform',
    scope: 'users:list',
    clientId: 'cid_m2m',
    subType: 'service',
  })}`
  assertEquals(
    (await app.request('/users/me/totp', {
      method: 'POST',
      headers: { Authorization },
    })).status,
    404,
  )
  assertEquals(
    (await app.request('/users/me/totp', {
      method: 'DELETE',
      headers: { Authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ code: '123456' }),
    })).status,
    404,
  )
})

Deno.test('a user cannot use the admin route on themselves', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const res = await ctx.call('DELETE', `/users/${ctx.user.id}/totp`)
  assertEquals(res.status, 403)
  // Still enabled: setup again is refused.
  assertEquals((await ctx.call('POST', '/users/me/totp')).status, 409)
})
