import { assertEquals } from '@std/assert'
import {
  decode,
  signAccessToken,
  verifyAccessToken,
  verifyWithKeyRing,
} from '../../src/lib/jwt.ts'
import { generateRsaKeyPairPem, loadKeyRing } from '../../src/lib/keys.ts'

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

Deno.test('signAccessToken writes the kid into the JWT header', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const ring = await loadKeyRing(privateKeyPem, publicKeyPem)
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://t',
    privateKeyPem,
    kid: ring.kid,
    ttlSeconds: 60,
    aud: 'a',
    org: 'o',
    scope: '',
    clientId: 'c',
  })
  const { header } = decode(token) as { header: { kid?: string } }
  assertEquals(header.kid, ring.kid)
})

Deno.test('verifyWithKeyRing verifies by kid, falls back to active, rejects unknown kid', async () => {
  const a = await generateRsaKeyPairPem()
  const ring = await loadKeyRing(a.privateKeyPem, a.publicKeyPem)
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://t',
    privateKeyPem: a.privateKeyPem,
    kid: ring.kid,
    ttlSeconds: 60,
    aud: 'a',
    org: 'o',
    scope: 'x',
    clientId: 'c',
  })
  const claims = await verifyWithKeyRing(token, ring)
  assertEquals(claims.sub, 'u1')

  // A token signed by a key not in the ring must be rejected.
  const b = await generateRsaKeyPairPem()
  const bRing = await loadKeyRing(b.privateKeyPem, b.publicKeyPem)
  const foreign = await signAccessToken({
    sub: 'u2',
    issuer: 'http://t',
    privateKeyPem: b.privateKeyPem,
    kid: bRing.kid,
    ttlSeconds: 60,
    aud: 'a',
    org: 'o',
    scope: '',
    clientId: 'c',
  })
  let threw = false
  try {
    await verifyWithKeyRing(foreign, ring)
  } catch {
    threw = true
  }
  assertEquals(threw, true)
})
