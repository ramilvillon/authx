import { assertEquals } from '@std/assert'
import { signAccessToken, verifyAccessToken } from '../../src/lib/jwt.ts'
import { generateRsaKeyPairPem } from '../../src/lib/keys.ts'

Deno.test('sign + verify access token (RS256)', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://localhost:3000',
    privateKeyPem,
    kid: 'k1',
    ttlSeconds: 900,
    aud: 'test-svc',
    org: 'o1',
    scope: '',
    clientId: 'cid_1',
  })
  const payload = await verifyAccessToken(token, publicKeyPem)
  assertEquals(payload.sub, 'u1')
  assertEquals(payload.iss, 'http://localhost:3000')
})

Deno.test('access token carries aud, org, scope', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'iss',
    privateKeyPem,
    kid: 'k1',
    ttlSeconds: 900,
    aud: 'acme-billing',
    org: 'o1',
    scope: 'billing:read billing:write',
    clientId: 'cid_1',
  })
  const p = await verifyAccessToken(token, publicKeyPem)
  assertEquals(p.aud, 'acme-billing')
  assertEquals(p.org, 'o1')
  assertEquals(p.scope, 'billing:read billing:write')
  assertEquals(p.client_id, 'cid_1')
})
