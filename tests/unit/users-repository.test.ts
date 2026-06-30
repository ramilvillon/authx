import { assertEquals } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'

Deno.test('in-memory user repo create + findByEmail + access', async () => {
  const repo = createInMemoryUserRepository()
  const now = new Date()
  const user = await repo.create({
    id: 'u1',
    email: 'a@b.com',
    passwordHash: 'h',
    createdAt: now,
    updatedAt: now,
  })
  assertEquals(user.email, 'a@b.com')
  assertEquals((await repo.findByEmail('a@b.com'))?.id, 'u1')

  await repo.assignRole('u1', 'user')
  const access = await repo.findWithAccessById('u1')
  assertEquals(access?.roles, ['user'])
  assertEquals(access?.permissions, [])
})

Deno.test('in-memory user repo with seeded role grants permissions', async () => {
  const repo = createInMemoryUserRepository({
    admin: ['users:list', 'users:delete:any'],
  })
  const now = new Date()
  await repo.create({
    id: 'u2',
    email: 'x@y.com',
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  await repo.assignRole('u2', 'admin')
  const access = await repo.findWithAccessById('u2')
  assertEquals(access?.permissions.sort(), ['users:delete:any', 'users:list'])
})
