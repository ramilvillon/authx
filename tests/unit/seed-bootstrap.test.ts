import { assertEquals, assertThrows } from '@std/assert'
import { bootstrapAdminFromEnv } from '../../src/db/seed.ts'

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
