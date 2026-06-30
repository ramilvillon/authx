import { assert, assertEquals } from '@std/assert'
import { hashPassword, verifyPassword } from '../../src/lib/password.ts'

Deno.test('hash + verify round-trips', async () => {
  const hash = await hashPassword('s3cret')
  assert(hash !== 's3cret')
  assertEquals(await verifyPassword('s3cret', hash), true)
  assertEquals(await verifyPassword('wrong', hash), false)
})
