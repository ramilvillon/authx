import { assert, assertEquals } from '@std/assert'
import { makeTestApp, submitLoginForm } from '../helpers.ts'
import { hashPassword } from '../../src/lib/password.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { hashToken } from '../../src/lib/tokens.ts'

// RFC 6749 section 2.3.1: client_secret_basic. A confidential client may send
// its credentials as `Authorization: Basic base64(id:secret)` instead of in the
// body -- the method servers MUST support, and the one openid-client and most
// server-side libraries default to.

const PASSWORD = 'pw123456'
const SECRET = 's3cret'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

type Ctx = ReturnType<typeof makeTestApp>

// Section 2.3.1: each half is application/x-www-form-urlencoded BEFORE the
// base64 step -- which is what a compliant client library sends.
const basic = (id: string, secret: string) => {
  const form = (v: string) => encodeURIComponent(v).replace(/%20/g, '+')
  return `Basic ${btoa(`${form(id)}:${form(secret)}`)}`
}

// Random names throughout: under `make test-db` every test shares one MySQL
// database between truncates.
async function seed(ctx: Ctx, secret = SECRET) {
  const now = new Date()
  const id = crypto.randomUUID()
  const email = `u-${id}@example.test`
  await ctx.userRepo.create({
    id,
    email,
    passwordHash: await hashPassword(PASSWORD),
    createdAt: now,
    updatedAt: now,
  })
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: `org-${id}`,
    name: 'Org',
    createdAt: now,
  })
  const clientId = `cid_conf_${id}`
  const audience = `aud-${id}`
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId,
    clientSecretHash: await hashToken(secret),
    name: 'Backend',
    slug: 'backend',
    audience,
    type: 'confidential',
    redirectUris: [REDIRECT],
    createdAt: now,
  })
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: id,
    orgId: org.id,
    createdAt: now,
  })
  return { email, clientId, audience }
}

const token = (
  ctx: Ctx,
  params: Record<string, string>,
  authorization?: string,
) =>
  ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(authorization ? { authorization } : {}),
    },
    body: new URLSearchParams(params).toString(),
  })

const clientCredentials = (s: Awaited<ReturnType<typeof seed>>) => ({
  grant_type: 'client_credentials',
  audience: s.audience,
})

async function assertInvalidClient(res: Response, challenged: boolean) {
  assertEquals(res.status, 401)
  assertEquals((await res.json()).error, 'invalid_client')
  const challenge = res.headers.get('www-authenticate')
  if (challenged) {
    // Section 5.2: required when the client authenticated via the header.
    assert(challenge?.startsWith('Basic '), `got ${challenge}`)
  } else {
    assertEquals(challenge, null, 'no Basic challenge for a body secret')
  }
}

// ---- it works ------------------------------------------------------------

Deno.test('client_credentials authenticates with HTTP Basic', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const res = await token(ctx, clientCredentials(s), basic(s.clientId, SECRET))
  assertEquals(res.status, 200)
  assert((await res.json()).access_token)
})

Deno.test('a confidential authorization_code exchange authenticates with HTTP Basic', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const login = await submitLoginForm(ctx.app, {
    email: s.email,
    password: PASSWORD,
    client_id: s.clientId,
    redirect_uri: REDIRECT,
    scope: '',
    state: 'xyz',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
  })
  assertEquals(login.status, 302, 'setup: login must issue a code')
  const code = new URL(login.headers.get('location')!).searchParams.get('code')!

  const res = await token(ctx, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT,
    code_verifier: VERIFIER,
  }, basic(s.clientId, SECRET))
  assertEquals(res.status, 200)
  assert((await res.json()).access_token)
})

Deno.test('Basic credentials are form-decoded after base64, as section 2.3.1 specifies', async () => {
  // A ':' would split the pair in the wrong place and '+' / '%' would be read
  // literally if the halves were not form-decoded.
  const secret = 's:e+c%ret'
  const ctx = makeTestApp()
  const s = await seed(ctx, secret)
  const res = await token(ctx, clientCredentials(s), basic(s.clientId, secret))
  assertEquals(res.status, 200)
})

// ---- failed client authentication ----------------------------------------

Deno.test('a wrong secret over Basic is 401 invalid_client with a Basic challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  await assertInvalidClient(
    await token(ctx, clientCredentials(s), basic(s.clientId, 'wrong')),
    true,
  )
})

Deno.test('an unknown client over Basic is 401 invalid_client with a Basic challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  await assertInvalidClient(
    await token(ctx, clientCredentials(s), basic('cid_nobody', SECRET)),
    true,
  )
})

Deno.test('a malformed Basic header is 401 invalid_client with a Basic challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  for (const header of ['Basic !!!not-base64', `Basic ${btoa('no-colon')}`]) {
    await assertInvalidClient(
      await token(ctx, clientCredentials(s), header),
      true,
    )
  }
})

Deno.test('a wrong secret in the body is 401 invalid_client with no Basic challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  await assertInvalidClient(
    await token(ctx, {
      ...clientCredentials(s),
      client_id: s.clientId,
      client_secret: 'wrong',
    }),
    false,
  )
})

// ---- the edges -----------------------------------------------------------

Deno.test('Basic plus a body client_secret is invalid_request (one method per request)', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  // Both halves are complete and correct, so the only thing wrong with this
  // request is that it authenticates twice.
  const res = await token(
    ctx,
    { ...clientCredentials(s), client_id: s.clientId, client_secret: SECRET },
    basic(s.clientId, SECRET),
  )
  assertEquals(res.status, 400)
  const body = await res.json()
  assertEquals(body.error, 'invalid_request')
  assert(
    body.error_description.includes('more than one'),
    `refused for the wrong reason: ${body.error_description}`,
  )
})

Deno.test('a body client_id that disagrees with the Basic header is invalid_request', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const res = await token(
    ctx,
    { ...clientCredentials(s), client_id: 'cid_someone_else' },
    basic(s.clientId, SECRET),
  )
  assertEquals(res.status, 400)
  const body = await res.json()
  assertEquals(body.error, 'invalid_request')
  assert(
    body.error_description.includes('Authorization header'),
    `refused for the wrong reason: ${body.error_description}`,
  )
})

Deno.test('a refresh authenticates with HTTP Basic', async () => {
  // The seeded service is confidential, so since client authentication on
  // refresh (confidential-refresh-auth.test.ts) these Basic credentials are
  // checked, not ignored.
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const first = await token(ctx, {
    grant_type: 'password',
    username: s.email,
    password: PASSWORD,
    audience: s.audience,
  })
  assertEquals(first.status, 200, 'setup: password grant')
  const res = await token(ctx, {
    grant_type: 'refresh_token',
    refresh_token: (await first.json()).refresh_token,
  }, basic(s.clientId, SECRET))
  assertEquals(res.status, 200)
})

Deno.test('discovery advertises client_secret_basic alongside client_secret_post', async () => {
  const ctx = makeTestApp()
  const doc = await (await ctx.app.request('/.well-known/openid-configuration'))
    .json()
  assertEquals(doc.token_endpoint_auth_methods_supported, [
    'client_secret_basic',
    'client_secret_post',
  ])
})
