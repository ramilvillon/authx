import { assert, assertEquals } from '@std/assert'
import { authHeader, makeTestApp } from '../helpers.ts'
import { signAccessToken } from '../../src/lib/jwt.ts'

async function register(app: ReturnType<typeof makeTestApp>['app']) {
  await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
}

Deno.test('password grant then /users/me', async () => {
  const { app } = makeTestApp()
  await register(app)
  const { Authorization } = await authHeader(app, 'a@b.com', 'pw123456')
  const res = await app.request('/users/me', { headers: { Authorization } })
  assertEquals(res.status, 200)
  assertEquals((await res.json()).email, 'a@b.com')
})

Deno.test('refresh rotation + revoke', async () => {
  const { app } = makeTestApp()
  await register(app)
  const { refresh } = await authHeader(app, 'a@b.com', 'pw123456')

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

Deno.test('/users/me without token -> 401', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users/me')
  assertEquals(res.status, 401)
})

Deno.test('/users/me rejects tampered, wrong-secret, and expired tokens', async () => {
  const { app } = makeTestApp()
  await register(app)
  const { Authorization } = await authHeader(app, 'a@b.com', 'pw123456')

  // tampered: flip the first char of the signature. The last base64url char of
  // a 32-byte HMAC signature only carries 4 significant bits, so flipping it can
  // decode to the same bytes (a no-op tamper); the first char always changes the
  // decoded signature, guaranteeing a genuine mismatch.
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

  // wrong secret
  const wrongSecret = await signAccessToken({
    sub: 'someone',
    secret: 'not-the-test-secret',
    ttlSeconds: 900,
  })
  assertEquals(
    (await app.request('/users/me', {
      headers: { Authorization: `Bearer ${wrongSecret}` },
    })).status,
    401,
  )

  // expired (negative ttl, signed with the correct secret)
  const expired = await signAccessToken({
    sub: 'someone',
    secret: 'test-secret',
    ttlSeconds: -1,
  })
  assertEquals(
    (await app.request('/users/me', {
      headers: { Authorization: `Bearer ${expired}` },
    })).status,
    401,
  )
})
