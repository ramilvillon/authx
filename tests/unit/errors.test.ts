import { assertEquals } from '@std/assert'
import { AppError, ERRORS } from '../../src/lib/errors.ts'

Deno.test('AppError.of maps a code to status + catalogue message', () => {
  const err = AppError.of('user_not_found')
  assertEquals(err.status, 404)
  assertEquals(err.code, 'user_not_found')
  assertEquals(err.message, 'user not found')
})

Deno.test('AppError.of message override keeps code + status', () => {
  const err = AppError.of('invalid_request', 'no service for acme')
  assertEquals(err.code, 'invalid_request')
  assertEquals(err.status, 400)
  assertEquals(err.message, 'no service for acme')
})

Deno.test('every catalogue entry has a positive status and a message', () => {
  for (const [code, e] of Object.entries(ERRORS)) {
    assertEquals(typeof e.message, 'string', code)
    assertEquals(e.status >= 400 && e.status < 600, true, code)
  }
})
