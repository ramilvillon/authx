import { assert, assertEquals, fail } from '@std/assert'
import { AppError } from '../../src/lib/errors.ts'
import { assertAcceptablePassword } from '../../src/lib/password-policy.ts'

// Not `assertThrows(fn, AppError)`: AppError's constructor is private (the
// AppError.of factory), so the class is not a constructor type. Same shape as
// tests/unit/guest-accounts.ts.
function codeOf(fn: () => void): string {
  try {
    fn()
  } catch (err) {
    assert(err instanceof AppError)
    return err.code
  }
  fail('expected the password to be refused')
}

Deno.test('a password from the common list is refused', () => {
  assertEquals(
    codeOf(() => assertAcceptablePassword('password123')),
    'weak_password',
  )
})

// The list is lowercased, so the check has to be too -- capitalising the first
// letter is the single most common way round a blocklist.
Deno.test('the common-password check ignores case', () => {
  assertEquals(
    codeOf(() => assertAcceptablePassword('Password123')),
    'weak_password',
  )
  assertEquals(
    codeOf(() => assertAcceptablePassword('QWERTY123')),
    'weak_password',
  )
})

Deno.test('a password shorter than the minimum is refused', () => {
  assertEquals(
    codeOf(() => assertAcceptablePassword('short1')),
    'weak_password',
  )
  assertEquals(
    codeOf(() => assertAcceptablePassword('elevenchar1', 12)),
    'weak_password',
  )
})

// bcrypt silently ignores everything past 72 bytes, so two long passwords
// sharing a prefix would authenticate each other. Refusing beats truncating.
Deno.test('a password over 72 bytes is refused rather than silently truncated', () => {
  assertEquals(
    codeOf(() => assertAcceptablePassword('a'.repeat(73))),
    'password_too_long',
  )
  assertAcceptablePassword('a'.repeat(72))
})

// 72 BYTES, not characters: bcrypt counts bytes, and one emoji is four.
Deno.test('the 72-byte limit counts bytes, not characters', () => {
  const emoji = '🔒'.repeat(19) // 76 bytes, 19 characters
  assertEquals(
    codeOf(() => assertAcceptablePassword(emoji)),
    'password_too_long',
  )
})

Deno.test('an ordinary strong password is accepted', () => {
  assertAcceptablePassword('correct horse battery staple')
  assertAcceptablePassword('pw123456')
})
