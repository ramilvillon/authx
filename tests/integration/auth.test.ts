import { assert, assertEquals } from '@std/assert'
import {
  authHeader,
  keySet,
  makeTestApp,
  seedDefaultService,
} from '../helpers.ts'
import { signAccessToken } from '../../src/lib/jwt.ts'
import { generateRsaKeyPairPem } from '../../src/lib/keys.ts'

// A different keypair — tokens signed with it are invalid on the test server.
const { privateKeyPem: wrongPrivateKeyPem } = await generateRsaKeyPairPem()

async function register(app: ReturnType<typeof makeTestApp>['app']) {
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
  return (await res.json()).id as string
}

Deno.test('password grant then /users/me', async () => {
  const { app, orgRepo } = makeTestApp()
  const userId = await register(app)
  const audience = await seedDefaultService(orgRepo, userId)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'pw123456',
    audience,
  )
  const res = await app.request('/users/me', { headers: { Authorization } })
  assertEquals(res.status, 200)
  assertEquals((await res.json()).email, 'a@b.com')
})

Deno.test('refresh rotation + revoke', async () => {
  const { app, orgRepo } = makeTestApp()
  const userId = await register(app)
  const audience = await seedDefaultService(orgRepo, userId)
  const { refresh } = await authHeader(app, 'a@b.com', 'pw123456', audience)

  const refreshed = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: refresh,
    }),
  })
  assertEquals(refreshed.status, 200)
  const next = await refreshed.json()
  assert(next.refresh_token !== refresh)

  const revoke = await app.request('/oauth/revoke', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ refresh_token: next.refresh_token }),
  })
  assertEquals(revoke.status, 204)

  // The revoked refresh token must now be rejected.
  const reuse = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: next.refresh_token,
    }),
  })
  assertEquals(reuse.status, 401)
})

Deno.test('deleting the user revokes its in-flight access token', async () => {
  const { app, orgRepo, userRepo } = makeTestApp()
  const userId = await register(app)
  const audience = await seedDefaultService(orgRepo, userId)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'pw123456',
    audience,
  )
  assertEquals(
    (await app.request('/users/me', { headers: { Authorization } })).status,
    200,
  )

  await userRepo.delete(userId)
  assertEquals(
    (await app.request('/users/me', { headers: { Authorization } })).status,
    401,
  )
})

// sub_type is an allow-list: only 'service' may skip the user-row check. A token
// without it (or with a value we never mint) must not outlive its subject.
Deno.test('a token without sub_type does not survive its user being deleted', async () => {
  const { app, userRepo } = makeTestApp()
  const userId = await register(app)
  const Authorization = `Bearer ${await signAccessToken(
    {
      sub: userId,
      issuer: 'http://test.local',
      privateKeyPem: keySet.privateKeyPem,
      kid: keySet.kid,
      ttlSeconds: 900,
      aud: 'test-service',
      org: 'o1',
      scope: '',
      clientId: 'cid',
    } as Parameters<typeof signAccessToken>[0],
  )}`

  await userRepo.delete(userId)
  assertEquals(
    (await app.request('/users/me', { headers: { Authorization } })).status,
    401,
  )
})

// The other side of that allow-list: a client-credentials token names an
// app-service, never a user row, and must still authenticate.
Deno.test('a service token authenticates without a user row', async () => {
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
    (await app.request('/users', { headers: { Authorization } })).status,
    200,
  )
})

// ...but it names no user row, so the one route that answers "who am I" has
// nothing to answer with. It must say so rather than invent a blank user.
Deno.test('a service token gets 404 from /users/me', async () => {
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
    (await app.request('/users/me', { headers: { Authorization } })).status,
    404,
  )
})

Deno.test('/users/me without token -> 401', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users/me')
  assertEquals(res.status, 401)
})

Deno.test('/users/me rejects tampered, wrong-key, and expired tokens', async () => {
  const { app, orgRepo } = makeTestApp()
  const userId = await register(app)
  const audience = await seedDefaultService(orgRepo, userId)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'pw123456',
    audience,
  )

  // tampered: flip the first char of the signature.
  const valid = Authorization.slice('Bearer '.length)
  const lastDot = valid.lastIndexOf('.')
  const sig = valid.slice(lastDot + 1)
  const tampered = valid.slice(0, lastDot + 1) +
    (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)
  assertEquals(
    (await app.request('/users/me', {
      headers: { Authorization: `Bearer ${tampered}` },
    })).status,
    401,
  )

  // wrong key: signed with a different RSA private key
  const wrongKey = await signAccessToken({
    sub: 'someone',
    issuer: 'http://test.local',
    privateKeyPem: wrongPrivateKeyPem,
    kid: 'wrong',
    ttlSeconds: 900,
    aud: 'test-service',
    org: 'o1',
    scope: '',
    clientId: 'cid',
    subType: 'user',
  })
  assertEquals(
    (await app.request('/users/me', {
      headers: { Authorization: `Bearer ${wrongKey}` },
    })).status,
    401,
  )

  // expired: signed with the correct key but negative TTL
  const expired = await signAccessToken({
    sub: 'someone',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: -1,
    aud: 'test-service',
    org: 'o1',
    scope: '',
    clientId: 'cid',
    subType: 'user',
  })
  assertEquals(
    (await app.request('/users/me', {
      headers: { Authorization: `Bearer ${expired}` },
    })).status,
    401,
  )
})
