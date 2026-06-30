import { assert, assertEquals } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { hashPassword } from '../../src/lib/password.ts'
import { verifyAccessToken } from '../../src/lib/jwt.ts'

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

// Seeds an org + service (with a redirect URI) and a member user with a password.
async function seedUserAndService(ctx: ReturnType<typeof makeTestDeps>) {
  const now = new Date()
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: 'a@b.com',
    passwordHash: await hashPassword('pw123456'),
    createdAt: now,
    updatedAt: now,
  })
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
    userId: user.id,
    orgId: org.id,
    createdAt: now,
  })
  return user
}

async function getCode(
  svc: ReturnType<typeof makeTestDeps>['deps']['authService'],
  userId: string,
) {
  const service = await svc.validateAuthorizeRequest({
    clientId: 'cid_app',
    redirectUri: REDIRECT,
    codeChallenge: await s256Challenge(VERIFIER),
    codeChallengeMethod: 'S256',
  })
  return await svc.issueAuthorizationCode(userId, service, {
    redirectUri: REDIRECT,
    scope: '',
    codeChallenge: await s256Challenge(VERIFIER),
    codeChallengeMethod: 'S256',
  })
}

Deno.test('authorization_code exchange returns a verifiable token pair', async () => {
  const ctx = makeTestDeps()
  const user = await seedUserAndService(ctx)
  const code = await getCode(ctx.deps.authService, user.id)
  const pair = await ctx.deps.authService.exchangeAuthorizationCode({
    code,
    redirectUri: REDIRECT,
    codeVerifier: VERIFIER,
    clientId: 'cid_app',
  })
  const claims = await verifyAccessToken(
    pair.access_token,
    ctx.deps.keySet.publicKeyPem,
  )
  assertEquals(claims.aud, 'acme-app')
  assert(pair.refresh_token.length > 0)
})

Deno.test('exchange rejects a bad PKCE verifier', async () => {
  const ctx = makeTestDeps()
  const user = await seedUserAndService(ctx)
  const code = await getCode(ctx.deps.authService, user.id)
  let threw = false
  try {
    await ctx.deps.authService.exchangeAuthorizationCode({
      code,
      redirectUri: REDIRECT,
      codeVerifier: 'wrong',
      clientId: 'cid_app',
    })
  } catch {
    threw = true
  }
  assert(threw)
})

Deno.test('exchange rejects a replayed code', async () => {
  const ctx = makeTestDeps()
  const user = await seedUserAndService(ctx)
  const code = await getCode(ctx.deps.authService, user.id)
  await ctx.deps.authService.exchangeAuthorizationCode({
    code,
    redirectUri: REDIRECT,
    codeVerifier: VERIFIER,
    clientId: 'cid_app',
  })
  let threw = false
  try {
    await ctx.deps.authService.exchangeAuthorizationCode({
      code,
      redirectUri: REDIRECT,
      codeVerifier: VERIFIER,
      clientId: 'cid_app',
    })
  } catch {
    threw = true
  }
  assert(threw)
})

Deno.test('loginCreateSession + userIdForSession round-trip; bad password throws', async () => {
  const ctx = makeTestDeps()
  const user = await seedUserAndService(ctx)
  const { token, userId } = await ctx.deps.authService.loginCreateSession(
    'a@b.com',
    'pw123456',
  )
  assertEquals(userId, user.id)
  assertEquals(await ctx.deps.authService.userIdForSession(token), user.id)
  await ctx.deps.authService.logout(token)
  assertEquals(await ctx.deps.authService.userIdForSession(token), null)

  let threw = false
  try {
    await ctx.deps.authService.loginCreateSession('a@b.com', 'wrong')
  } catch {
    threw = true
  }
  assert(threw)
})
