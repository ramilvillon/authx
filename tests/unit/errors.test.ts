import { assertEquals } from '@std/assert'
import { AppError } from '../../src/lib/errors.ts'

Deno.test('AppError.notFound sets status and code', () => {
  const err = AppError.notFound('user not found')
  assertEquals(err.status, 404)
  assertEquals(err.code, 'not_found')
  assertEquals(err.message, 'user not found')
})

Deno.test('AppError.conflict sets 409', () => {
  assertEquals(AppError.conflict('dup').status, 409)
})
