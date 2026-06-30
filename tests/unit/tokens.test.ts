import { assert, assertEquals } from '@std/assert'
import { generateRefreshToken, hashToken } from '../../src/lib/tokens.ts'

Deno.test('refresh token is opaque and hashable', async () => {
  const token = generateRefreshToken()
  assert(token.length >= 32)
  const h = await hashToken(token)
  assertEquals(h, await hashToken(token))
  assert(h !== token)
})
