import { assertEquals } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'

function guestRow(username: string) {
  const now = new Date()
  return {
    id: crypto.randomUUID(),
    email: null,
    username,
    passwordHash: 'x',
    createdAt: now,
    updatedAt: now,
  }
}

Deno.test('findByUsername finds a guest that has no email', async () => {
  const repo = createInMemoryUserRepository()
  const created = await repo.create(guestRow('guest_abc'))
  const found = await repo.findByUsername('guest_abc')
  assertEquals(found?.id, created.id)
  assertEquals(found?.email, null)
})

Deno.test('findByUsername hides a soft-deleted guest', async () => {
  const repo = createInMemoryUserRepository()
  const created = await repo.create(guestRow('guest_gone'))
  await repo.softDelete(created.id)
  assertEquals(await repo.findByUsername('guest_gone'), null)
})

// The divergence guard. A Map compares null === null and matches; MySQL's
// `WHERE email = NULL` never does. Without an explicit guard the in-memory
// double is more permissive than the database, which is how three real bugs
// have already hidden behind a green suite.
Deno.test('an email lookup never matches a row that has no email', async () => {
  const repo = createInMemoryUserRepository()
  await repo.create(guestRow('guest_nomail'))
  assertEquals(
    await repo.findByEmail(null as unknown as string),
    null,
    'findByEmail(null) must not match a null-email row',
  )
  assertEquals(
    await repo.findAnyByEmail(null as unknown as string),
    null,
    'findAnyByEmail(null) must not match a null-email row',
  )
})

Deno.test('two guests can coexist with no email', async () => {
  const repo = createInMemoryUserRepository()
  await repo.create(guestRow('guest_one'))
  await repo.create(guestRow('guest_two'))
  assertEquals((await repo.list()).length, 2)
})
