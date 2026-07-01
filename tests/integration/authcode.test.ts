import { assert, assertEquals } from '@std/assert'
import { keySet, makeTestApp } from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { verifyAccessToken } from '../../src/lib/jwt.ts'

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

async function seed(ctx: ReturnType<typeof makeTestApp>) {
  // Register the user (sets a password hash) via the public endpoint.
  await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
  const now = new Date()
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: 'acme',
    name: 'Acme',
    createdAt: now,
  })
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: 'cid_app',
    clientSecretHash: null,
    name: 'App',
    slug: 'app',
    audience: 'acme-app',
    type: 'public',
    redirectUris: [REDIRECT],
    createdAt: now,
  })
  // Find the registered user's id to add membership.
  const user = await ctx.userRepo.findByEmail('a@b.com')
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: user!.id,
    orgId: org.id,
    createdAt: now,
  })
}

function authorizeForm(challenge: string, extra: Record<string, string> = {}) {
  return new URLSearchParams({
    email: 'a@b.com',
    password: 'pw123456',
    client_id: 'cid_app',
    redirect_uri: REDIRECT,
    scope: '',
    state: 'xyz',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  })
}

Deno.test('full auth-code flow: login -> code -> token -> verify', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)

  const loginRes = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: authorizeForm(challenge).toString(),
    redirect: 'manual',
  })
  assertEquals(loginRes.status, 302)
  const location = loginRes.headers.get('location')!
  const url = new URL(location)
  assertEquals(url.origin + url.pathname, REDIRECT)
  assertEquals(url.searchParams.get('state'), 'xyz')
  const code = url.searchParams.get('code')!
  assert(code.length > 0)
  const cookie = loginRes.headers.get('set-cookie')!
  assert(cookie.includes('authx_session='))

  const tokenRes = await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      client_id: 'cid_app',
    }),
  })
  assertEquals(tokenRes.status, 200)
  const pair = await tokenRes.json()
  const claims = await verifyAccessToken(pair.access_token, keySet.publicKeyPem)
  assertEquals(claims.aud, 'acme-app')

  // SSO: with the session cookie, GET /authorize redirects straight to a code.
  const ssoRes = await ctx.app.request(
    `/oauth/authorize?client_id=cid_app&redirect_uri=${
      encodeURIComponent(REDIRECT)
    }&scope=&state=s2&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { cookie: cookie.split(';')[0] }, redirect: 'manual' },
  )
  assertEquals(ssoRes.status, 302)
  assert(new URL(ssoRes.headers.get('location')!).searchParams.get('code'))
})

Deno.test('GET /authorize without a session renders the login form', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const res = await ctx.app.request(
    `/oauth/authorize?client_id=cid_app&redirect_uri=${
      encodeURIComponent(REDIRECT)
    }&scope=&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
    { redirect: 'manual' },
  )
  assertEquals(res.status, 200)
  assert((await res.text()).includes('<form'))
})

Deno.test('bad redirect_uri is rejected, never redirected', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const res = await ctx.app.request(
    `/oauth/authorize?client_id=cid_app&redirect_uri=${
      encodeURIComponent('https://evil.example/cb')
    }&scope=&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
    { redirect: 'manual' },
  )
  assertEquals(res.status, 400)
})

Deno.test('replayed code is rejected at the token endpoint', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const loginRes = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: authorizeForm(challenge).toString(),
    redirect: 'manual',
  })
  const code = new URL(loginRes.headers.get('location')!).searchParams.get(
    'code',
  )!
  const body = JSON.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT,
    code_verifier: VERIFIER,
    client_id: 'cid_app',
  })
  const ok = await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  })
  assertEquals(ok.status, 200)
  const replay = await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  })
  assertEquals(replay.status, 400)
})

Deno.test('wrong password re-renders the form with 401', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const res = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: authorizeForm(challenge, { password: 'wrong' }).toString(),
    redirect: 'manual',
  })
  assertEquals(res.status, 401)
})
