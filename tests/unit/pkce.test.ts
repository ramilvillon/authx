import { assert, assertEquals } from '@std/assert'
import { s256Challenge, verifyChallenge } from '../../src/lib/pkce.ts'

// RFC 7636 Appendix B test vector.
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

Deno.test('s256Challenge matches the RFC 7636 vector', async () => {
  assertEquals(await s256Challenge(VERIFIER), CHALLENGE)
})

Deno.test('verifyChallenge: true for the right verifier, false otherwise', async () => {
  assert(await verifyChallenge(VERIFIER, CHALLENGE))
  assert(!(await verifyChallenge('wrong-verifier', CHALLENGE)))
})
