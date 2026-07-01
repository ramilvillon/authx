import { assert, assertEquals } from '@std/assert'
import { keySet, makeTestApp } from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { decode, verifyAccessToken } from '../../src/lib/jwt.ts'

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

async function seed(ctx: ReturnType<typeof makeTestApp>) {
  await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
  const user = await ctx.userRepo.findByEmail('a@b.com')
  await ctx.userRepo.update(user!.id, { name: 'Ada L' })
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
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: user!.id,
    orgId: org.id,
    createdAt: now,
  })
}

function form(challenge: string, scope: string) {
  return new URLSearchParams({
    email: 'a@b.com',
    password: 'pw123456',
    client_id: 'cid_app',
    redirect_uri: REDIRECT,
    scope,
    state: 's',
    nonce: 'n-123',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()
}

async function codeFromLogin(
  ctx: ReturnType<typeof makeTestApp>,
  challenge: string,
  scope: string,
) {
  const res = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form(challenge, scope),
    redirect: 'manual',
  })
  return new URL(res.headers.get('location')!).searchParams.get('code')!
}

async function exchange(ctx: ReturnType<typeof makeTestApp>, code: string) {
  const res = await ctx.app.request('/oauth/token', {
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
  return await res.json()
}

Deno.test('openid code flow returns an id_token with standard claims', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const code = await codeFromLogin(ctx, challenge, 'openid email profile')
  const body = await exchange(ctx, code)

  assert(typeof body.id_token === 'string')
  const { payload } = decode(body.id_token) as {
    payload: Record<string, unknown>
  }
  const user = await ctx.userRepo.findByEmail('a@b.com')
  assertEquals(payload.sub, user!.id)
  assertEquals(payload.aud, 'cid_app') // id_token aud = client_id
  assertEquals(payload.nonce, 'n-123')
  assertEquals(payload.email, 'a@b.com')
  assertEquals(payload.name, 'Ada L')
  assert(typeof payload.auth_time === 'number')

  // access token still targets the service audience and carries oidc_scope
  const claims = await verifyAccessToken(body.access_token, keySet.publicKeyPem)
  assertEquals(claims.aud, 'acme-app')
  assertEquals(claims.oidc_scope, 'openid email profile')
})

Deno.test('non-openid code flow returns NO id_token', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const code = await codeFromLogin(ctx, challenge, 'email') // no openid
  const body = await exchange(ctx, code)
  assertEquals(body.id_token, undefined)
})

Deno.test('an id_token is rejected as a Bearer access token', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const code = await codeFromLogin(ctx, challenge, 'openid email')
  const body = await exchange(ctx, code)
  const res = await ctx.app.request('/users/me', {
    headers: { authorization: `Bearer ${body.id_token}` },
  })
  assertEquals(res.status, 401)
})

Deno.test('a verified user gets email_verified:true in the id_token', async () => {
  const ctx = makeTestApp()
  await seed(ctx) // registers a@b.com and seeds the service (existing helper)
  // verify the email using the captured link
  const token = new URL(ctx.sentEmails[0].link).searchParams.get('token')!
  await ctx.app.request(`/verify-email?token=${token}`)

  const challenge = await s256Challenge(VERIFIER)
  const code = await codeFromLogin(ctx, challenge, 'openid email')
  const body = await exchange(ctx, code)
  const { payload } = decode(body.id_token) as {
    payload: Record<string, unknown>
  }
  assertEquals(payload.email_verified, true)
})
