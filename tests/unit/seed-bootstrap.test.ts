import { assertEquals, assertThrows } from '@std/assert'
import {
  bootstrapAdminAction,
  bootstrapAdminFromEnv,
} from '../../src/db/seed.ts'

Deno.test('bootstrapAdminFromEnv refuses the shipped placeholder password', () => {
  assertThrows(
    () => bootstrapAdminFromEnv('admin@example.com', 'change-me-please'),
    Error,
    'BOOTSTRAP_ADMIN_PASSWORD',
  )
})

Deno.test('bootstrapAdminFromEnv skips (does not refuse) a half-set pair', () => {
  assertEquals(bootstrapAdminFromEnv('', 'change-me-please'), null)
  assertEquals(bootstrapAdminFromEnv(undefined, 'change-me-please'), null)
  assertEquals(bootstrapAdminFromEnv('admin@example.com', undefined), null)
})

Deno.test('bootstrapAdminFromEnv passes any other password through', () => {
  assertEquals(bootstrapAdminFromEnv('a@b.com', 'change-me'), {
    email: 'a@b.com',
    password: 'change-me',
  })
})

// Step 5's decision about an account that already has BOOTSTRAP_ADMIN_EMAIL.
// The seed used to adopt ANY such row and make it platform admin, keeping that
// row's own password -- so whoever registered the address first became admin.

Deno.test('bootstrapAdminAction creates the admin when no account has the address', () => {
  assertEquals(bootstrapAdminAction(null), 'create')
})

Deno.test('bootstrapAdminAction adopts an account that is already platform admin (an idempotent re-run)', () => {
  assertEquals(
    bootstrapAdminAction({ hasAdminRole: true, passwordMatches: true }),
    'adopt',
  )
})

Deno.test('bootstrapAdminAction still adopts the admin after its password was changed through the API', () => {
  // Re-running the seed with the original env password must not start failing
  // the moment the admin rotates their password.
  assertEquals(
    bootstrapAdminAction({ hasAdminRole: true, passwordMatches: false }),
    'adopt',
  )
})

Deno.test('bootstrapAdminAction adopts a non-admin account whose password the operator knows', () => {
  // The operator registered themselves first, then pointed the seed at their
  // own address. Knowing the password is the proof they control it.
  assertEquals(
    bootstrapAdminAction({ hasAdminRole: false, passwordMatches: true }),
    'adopt',
  )
})

Deno.test('bootstrapAdminAction refuses a non-admin account whose password the operator does not know', () => {
  // Someone else registered the address before the seed ran. Adopting it would
  // hand them platform admin with their own password.
  assertEquals(
    bootstrapAdminAction({ hasAdminRole: false, passwordMatches: false }),
    'refuse',
  )
})
