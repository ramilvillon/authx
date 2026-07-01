import { assertEquals } from '@std/assert'
import { keySet, makeTestApp } from '../helpers.ts'
import { hashToken } from '../../src/lib/tokens.ts'
import { verifyAccessToken } from '../../src/lib/jwt.ts'

async function seed(ctx: ReturnType<typeof makeTestApp>) {
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
    clientId: 'cid_client',
    clientSecretHash: await hashToken('s3cret'),
    name: 'Caller',
    slug: 'caller',
    audience: 'caller-aud',
    type: 'confidential',
    redirectUris: [],
    createdAt: now,
  })
  await ctx.orgRepo.createService({
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
}

function tokenReq(body: Record<string, string>) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }
}

Deno.test('client_credentials over /oauth/token returns a token, no refresh', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const res = await ctx.app.request(
    '/oauth/token',
    tokenReq({
      grant_type: 'client_credentials',
      client_id: 'cid_client',
      client_secret: 's3cret',
      audience: 'target-aud',
    }),
  )
  assertEquals(res.status, 200)
  const body = await res.json()
  assertEquals(body.refresh_token, undefined)
  const claims = await verifyAccessToken(body.access_token, keySet.publicKeyPem)
  assertEquals(claims.aud, 'target-aud')
  assertEquals(claims.client_id, 'cid_client')
})

Deno.test('client_credentials rejects a wrong secret with 401', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const res = await ctx.app.request(
    '/oauth/token',
    tokenReq({
      grant_type: 'client_credentials',
      client_id: 'cid_client',
      client_secret: 'wrong',
      audience: 'target-aud',
    }),
  )
  assertEquals(res.status, 401)
})
