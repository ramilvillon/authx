import { assertEquals, assertRejects } from '@std/assert'
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

// The double is only useful while it refuses what MySQL refuses. These four
// are the constraints on `users` a Map does not have: the PRIMARY key and the
// UNIQUE indexes on email and username, all under a case-insensitive
// collation. Without them the suite can prove behaviour the database would
// never allow -- which is how the email-change path shipped with no
// uniqueness guard and a green suite.
Deno.test('in-memory user repo enforces the UNIQUE indexes MySQL has', async () => {
  const repo = createInMemoryUserRepository()
  const now = new Date()
  const row = (over: Partial<Parameters<typeof repo.create>[0]>) => ({
    id: crypto.randomUUID(),
    email: null,
    passwordHash: 'h',
    createdAt: now,
    updatedAt: now,
    ...over,
  })
  await repo.create(row({ id: 'u1', email: 'a@b.com', username: 'guest_1' }))

  await assertRejects(
    () => repo.create(row({ id: 'u1', email: 'other@b.com' })),
    Error,
    'duplicate users.id',
  )
  await assertRejects(
    () => repo.create(row({ email: 'a@b.com' })),
    Error,
    'duplicate users.email',
  )
  await assertRejects(
    () => repo.create(row({ email: 'A@B.COM' })),
    Error,
    'duplicate users.email',
  )
  await assertRejects(
    () => repo.create(row({ username: 'GUEST_1' })),
    Error,
    'duplicate users.username',
  )

  // Many NULLs coexist under a UNIQUE index in MySQL, so two address-less
  // guests and two email-only users must both be fine.
  await repo.create(row({ username: 'guest_2' }))
  await repo.create(row({ email: 'c@b.com' }))

  // An UPDATE onto an address another row holds is the same violation.
  const mover = await repo.create(row({ email: 'mover@b.com' }))
  await assertRejects(
    () => repo.update(mover.id, { email: 'A@b.com' }),
    Error,
    'duplicate users.email',
  )
  // Rewriting your own address, in any case, is not a conflict with yourself.
  assertEquals(
    (await repo.update(mover.id, { email: 'MOVER@b.com' }))?.email,
    'MOVER@b.com',
  )
})
