import { assert, assertEquals } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'
import { hashToken } from '../../src/lib/tokens.ts'
import { verifyAccessToken } from '../../src/lib/jwt.ts'

// Seeds a confidential requesting client + a target service, returns their ids/secret.
async function seed(ctx: ReturnType<typeof makeTestDeps>) {
  const now = new Date()
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: 'acme',
    name: 'Acme',
    createdAt: now,
  })
  const secret = 's3cret-value'
  const client = await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: 'cid_client',
    clientSecretHash: await hashToken(secret),
    name: 'Caller',
    slug: 'caller',
    audience: 'caller-aud',
    type: 'confidential',
    redirectUris: [],
    createdAt: now,
  })
  const target = await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: 'cid_target',
    clientSecretHash: null,
    name: 'Target',
    slug: 'target',
    audience: 'target-aud',
    type: 'public',
    redirectUris: [],
    createdAt: now,
  })
  return { client, target, secret }
}

Deno.test('client_credentials issues a scoped token, no refresh', async () => {
  const ctx = makeTestDeps()
  const { client, target, secret } = await seed(ctx)
  // grant the client a role in the target service
  await ctx.rbacRepo.createRole({
    id: 'r1',
    appServiceId: target.id,
    name: 'writer',
  })
  await ctx.rbacRepo.createPermission({
    id: 'p1',
    appServiceId: target.id,
    key: 'orders:write',
  })
  await ctx.rbacRepo.grantPermissionToRole('r1', 'p1')
  await ctx.rbacRepo.assignRoleToClient(client.id, 'r1')

  const res = await ctx.deps.authService.clientCredentialsGrant(
    'cid_client',
    secret,
    'target-aud',
  )
  assertEquals((res as { refresh_token?: string }).refresh_token, undefined)
  const claims = await verifyAccessToken(
    res.access_token,
    ctx.deps.keySet.publicKeyPem,
  )
  assertEquals(claims.aud, 'target-aud')
  assertEquals(claims.sub, client.id)
  assertEquals(claims.client_id, 'cid_client')
  assertEquals(claims.scope, 'orders:write')
})

Deno.test('client_credentials rejects wrong secret, public client, unknown audience', async () => {
  const ctx = makeTestDeps()
  const { secret } = await seed(ctx)
  const throws = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      return false
    } catch {
      return true
    }
  }
  assert(
    await throws(() =>
      ctx.deps.authService.clientCredentialsGrant(
        'cid_client',
        'wrong',
        'target-aud',
      )
    ),
  )
  // public client (cid_target has no secret) cannot use the grant
  assert(
    await throws(() =>
      ctx.deps.authService.clientCredentialsGrant(
        'cid_target',
        secret,
        'target-aud',
      )
    ),
  )
  // unknown audience
  assert(
    await throws(() =>
      ctx.deps.authService.clientCredentialsGrant('cid_client', secret, 'nope')
    ),
  )
})

Deno.test('client_credentials issues an empty-scope token when the client has no roles', async () => {
  const ctx = makeTestDeps()
  const { secret } = await seed(ctx)
  const res = await ctx.deps.authService.clientCredentialsGrant(
    'cid_client',
    secret,
    'target-aud',
  )
  const claims = await verifyAccessToken(
    res.access_token,
    ctx.deps.keySet.publicKeyPem,
  )
  assertEquals(claims.scope, '')
})
