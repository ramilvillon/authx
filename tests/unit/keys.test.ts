import { assertEquals, assertExists } from '@std/assert'
import { generateRsaKeyPairPem, loadKeySet } from '../../src/lib/keys.ts'
import type { Jwk } from '../../src/lib/keys.ts'

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
