import { assertEquals } from '@std/assert'
import { signAccessToken, verifyAccessToken } from '../../src/lib/jwt.ts'

Deno.test('sign + verify access token', async () => {
  const token = await signAccessToken({
    sub: 'u1',
    secret: 'sec',
    ttlSeconds: 900,
  })
  const payload = await verifyAccessToken(token, 'sec')
  assertEquals(payload.sub, 'u1')
})
