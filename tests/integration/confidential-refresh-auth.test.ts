import { assert, assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'
import { hashPassword } from '../../src/lib/password.ts'
import { hashToken } from '../../src/lib/tokens.ts'

// RFC 6749 section 6 and RFC 7009 section 2.1: a refresh token that belongs to
// a confidential client can only be used or revoked with that client's
// credentials. Before this, the token alone was enough. Public clients have no
// secret to send and are unchanged.

const PASSWORD = 'pw123456'
const SECRET_A = 'secret-a'
const SECRET_B = 'secret-b'

type Ctx = ReturnType<typeof makeTestApp>
type Seeded = Awaited<ReturnType<typeof seed>>

const basic = (id: string, secret: string) =>
  `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`

// Random names throughout: under `make test-db` every test shares one MySQL
// database between truncates.
async function seed(ctx: Ctx) {
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
  const service = async (
    name: string,
    type: 'public' | 'confidential',
    secret: string | null,
  ) => {
    const clientId = `cid_${name}_${id}`
    const audience = `${name}-${id}`
    await ctx.orgRepo.createService({
      id: crypto.randomUUID(),
      orgId: org.id,
      clientId,
      clientSecretHash: secret ? await hashToken(secret) : null,
      name,
      slug: name,
      audience,
      type,
      redirectUris: [],
      createdAt: now,
    })
    return { clientId, audience }
  }
  const confA = await service('conf-a', 'confidential', SECRET_A)
  const confB = await service('conf-b', 'confidential', SECRET_B)
  const pub = await service('pub', 'public', null)
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: id,
    orgId: org.id,
    createdAt: now,
  })
  return { email, confA, confB, pub }
}

const post = (
  ctx: Ctx,
  path: string,
  params: Record<string, string>,
  authorization?: string,
) =>
  ctx.app.request(path, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(authorization ? { authorization } : {}),
    },
    body: new URLSearchParams(params).toString(),
  })

// A refresh token issued for `audience` -- and so belonging to that service.
async function refreshTokenFor(ctx: Ctx, s: Seeded, audience: string) {
  const res = await post(ctx, '/oauth/token', {
    grant_type: 'password',
    username: s.email,
    password: PASSWORD,
    audience,
  })
  assertEquals(res.status, 200, 'setup: password grant')
  return (await res.json()).refresh_token as string
}

const refresh = (
  ctx: Ctx,
  token: string,
  client: Record<string, string> = {},
  authorization?: string,
) =>
  post(ctx, '/oauth/token', {
    grant_type: 'refresh_token',
    refresh_token: token,
    ...client,
  }, authorization)

const revoke = (
  ctx: Ctx,
  token: string,
  client: Record<string, string> = {},
  authorization?: string,
) =>
  post(ctx, '/oauth/revoke', { refresh_token: token, ...client }, authorization)

async function assertError(
  res: Response,
  status: number,
  error: string,
  challenged = false,
) {
  assertEquals(res.status, status)
  assertEquals((await res.json()).error, error)
  const challenge = res.headers.get('www-authenticate')
  if (challenged) assert(challenge?.startsWith('Basic '), `got ${challenge}`)
  else assertEquals(challenge, null)
}

// ---- refresh: confidential ------------------------------------------------

Deno.test('refresh: a confidential token refreshes with its client credentials in the body', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  const res = await refresh(ctx, t, {
    client_id: s.confA.clientId,
    client_secret: SECRET_A,
  })
  assertEquals(res.status, 200)
})

Deno.test('refresh: a confidential token refreshes with HTTP Basic', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  const res = await refresh(ctx, t, {}, basic(s.confA.clientId, SECRET_A))
  assertEquals(res.status, 200)
})

Deno.test('refresh: a confidential token without client credentials is invalid_client', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(await refresh(ctx, t), 401, 'invalid_client')
})

Deno.test('refresh: a wrong client secret in the body is invalid_client with no challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(
    await refresh(ctx, t, { client_id: s.confA.clientId, client_secret: 'no' }),
    401,
    'invalid_client',
  )
})

Deno.test('refresh: a wrong client secret over Basic is invalid_client with a challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(
    await refresh(ctx, t, {}, basic(s.confA.clientId, 'no')),
    401,
    'invalid_client',
    true,
  )
})

Deno.test('refresh: the right secret without a client_id is invalid_client', async () => {
  // Client authentication is id AND secret (RFC 6749 section 2.3.1).
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(
    await refresh(ctx, t, { client_secret: SECRET_A }),
    401,
    'invalid_client',
  )
})

Deno.test("refresh: another client's valid credentials cannot refresh this client's token", async () => {
  // B authenticates perfectly well -- as B. The token was issued to A.
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(
    await refresh(ctx, t, {}, basic(s.confB.clientId, SECRET_B)),
    400,
    'invalid_grant',
  )
})

Deno.test('refresh: an unauthenticated replay of a rotated confidential token does not revoke the family', async () => {
  // Client authentication runs BEFORE reuse detection. Otherwise anyone
  // holding a stale token -- but not the secret -- could revoke the real
  // client's whole session.
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const creds = { client_id: s.confA.clientId, client_secret: SECRET_A }
  const old = await refreshTokenFor(ctx, s, s.confA.audience)
  const rotated = await refresh(ctx, old, creds)
  assertEquals(rotated.status, 200, 'setup: first rotation')
  const current = (await rotated.json()).refresh_token

  await assertError(await refresh(ctx, old), 401, 'invalid_client')

  assertEquals(
    (await refresh(ctx, current, creds)).status,
    200,
    'the replay must not have revoked the current token',
  )
})

// ---- refresh: public --------------------------------------------------------

Deno.test('refresh: a public token still refreshes with no client credentials', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.pub.audience)
  assertEquals((await refresh(ctx, t)).status, 200)
})

Deno.test("refresh: a public token presented with another service's client_id is invalid_grant", async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.pub.audience)
  await assertError(
    await refresh(ctx, t, { client_id: s.confA.clientId }),
    400,
    'invalid_grant',
  )
})

Deno.test('refresh: replaying a rotated public token still revokes the family', async () => {
  // The reordering must not have weakened reuse detection where it matters.
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const old = await refreshTokenFor(ctx, s, s.pub.audience)
  const rotated = await refresh(ctx, old)
  assertEquals(rotated.status, 200, 'setup: first rotation')
  const current = (await rotated.json()).refresh_token

  await assertError(await refresh(ctx, old), 400, 'invalid_grant')
  await assertError(await refresh(ctx, current), 400, 'invalid_grant')
})

// ---- revoke -----------------------------------------------------------------

Deno.test('revoke: a confidential token is revoked with its client credentials', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const creds = { client_id: s.confA.clientId, client_secret: SECRET_A }
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  assertEquals((await revoke(ctx, t, creds)).status, 204)
  await assertError(await refresh(ctx, t, creds), 400, 'invalid_grant')
})

Deno.test('revoke: a confidential token without client credentials is invalid_client and survives', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(await revoke(ctx, t), 401, 'invalid_client')
  assertEquals(
    (await refresh(ctx, t, {
      client_id: s.confA.clientId,
      client_secret: SECRET_A,
    })).status,
    200,
    'a refused revoke must leave the token alive',
  )
})

Deno.test('revoke: a wrong secret over Basic is invalid_client with a challenge', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(
    await revoke(ctx, t, {}, basic(s.confA.clientId, 'no')),
    401,
    'invalid_client',
    true,
  )
})

Deno.test("revoke: another client's valid credentials cannot revoke this client's token", async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.confA.audience)
  await assertError(
    await revoke(ctx, t, {}, basic(s.confB.clientId, SECRET_B)),
    401,
    'invalid_client',
    true,
  )
})

Deno.test('revoke: a public token is still revoked with no client credentials', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const t = await refreshTokenFor(ctx, s, s.pub.audience)
  assertEquals((await revoke(ctx, t)).status, 204)
  await assertError(await refresh(ctx, t), 400, 'invalid_grant')
})

Deno.test('revoke: an unknown token is still 204 (RFC 7009)', async () => {
  const ctx = makeTestApp()
  assertEquals((await revoke(ctx, 'not-a-token')).status, 204)
})
