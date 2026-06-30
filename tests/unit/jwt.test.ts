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
  })
  const payload = await verifyAccessToken(token, publicKeyPem)
  assertEquals(payload.sub, 'u1')
  assertEquals(payload.iss, 'http://localhost:3000')
})
