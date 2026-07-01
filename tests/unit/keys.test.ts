import { assertEquals, assertExists } from '@std/assert'
import { generateRsaKeyPairPem, loadKeySet } from '../../src/lib/keys.ts'
import type { Jwk } from '../../src/lib/keys.ts'
import { loadKeyRing } from '../../src/lib/keys.ts'

Deno.test('loadKeySet builds a JWKS with a stable kid from the public key', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const ks = await loadKeySet(privateKeyPem, publicKeyPem)
  assertEquals(ks.jwks.keys.length, 1)
  const jwk: Jwk = ks.jwks.keys[0]
  assertEquals(jwk.kty, 'RSA')
  assertEquals(jwk.alg, 'RS256')
  assertEquals(jwk.use, 'sig')
  assertEquals(jwk.kid, ks.kid)
  assertExists(jwk.n)
  // No private material leaks into the JWKS.
  assertEquals((jwk as unknown as Record<string, unknown>).d, undefined)
  // kid is deterministic for the same key.
  const again = await loadKeySet(privateKeyPem, publicKeyPem)
  assertEquals(again.kid, ks.kid)
})

Deno.test('loadKeyRing lists active + previous public keys in JWKS and byKid', async () => {
  const a = await generateRsaKeyPairPem()
  const b = await generateRsaKeyPairPem()
  const ring = await loadKeyRing(a.privateKeyPem, a.publicKeyPem, [
    b.publicKeyPem,
  ])
  assertEquals(ring.jwks.keys.length, 2)
  assertEquals(ring.byKid.size, 2)
  // active fields point at the active key
  assertEquals(ring.publicKeyPem, a.publicKeyPem)
  assertEquals(ring.byKid.get(ring.kid), a.publicKeyPem)
  // the active kid is the first JWKS entry
  assertEquals(ring.jwks.keys[0].kid, ring.kid)
})
