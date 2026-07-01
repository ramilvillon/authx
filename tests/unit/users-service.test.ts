import { assertEquals, assertRejects } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'
import { createUserService } from '../../src/modules/users/users.service.ts'
import { verifyPassword } from '../../src/lib/password.ts'

function service() {
  const repo = createInMemoryUserRepository({ user: [] })
  return { repo, svc: createUserService({ repo }) }
}

Deno.test('register creates user with default role and hashed password', async () => {
  const { repo, svc } = service()
  const user = await svc.register({ email: 'a@b.com', password: 'pw123456' })
  assertEquals(user.email, 'a@b.com')
  const stored = await repo.findById(user.id)
  assertEquals(await verifyPassword('pw123456', stored!.passwordHash!), true)
  const access = await repo.findWithAccessById(user.id)
  assertEquals(access?.roles, ['user'])
})

Deno.test('register rejects duplicate email', async () => {
  const { svc } = service()
  await svc.register({ email: 'a@b.com', password: 'pw123456' })
  await assertRejects(
    () => svc.register({ email: 'a@b.com', password: 'pw123456' }),
    Error,
    'already registered',
  )
})

Deno.test('update persists OIDC profile fields', async () => {
  const repo = createInMemoryUserRepository()
  const svc = createUserService({ repo })
  const now = new Date()
  const created = await repo.create({
    id: 'u1',
    email: 'a@b.com',
    passwordHash: 'h',
    createdAt: now,
    updatedAt: now,
  })
  await svc.update(created.id, {
    name: 'Ada L',
    given_name: 'Ada',
    family_name: 'L',
    email_verified: true,
  })
  const rec = await repo.findById('u1')
  assertEquals(rec?.name, 'Ada L')
  assertEquals(rec?.givenName, 'Ada')
  assertEquals(rec?.emailVerified, true)
})
