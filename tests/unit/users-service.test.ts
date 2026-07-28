import { assertEquals, assertRejects } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'
import { createUserService } from '../../src/modules/users/users.service.ts'
import { updateUserSchema } from '../../src/modules/users/users.schema.ts'
import { verifyPassword } from '../../src/lib/password.ts'
import { createInMemoryRefreshTokenRepository } from '../../src/modules/auth/token.repository.ts'
import { createInMemorySessionRepository } from '../../src/modules/auth/session.repository.ts'

function service(repo = createInMemoryUserRepository({ user: [] })) {
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const sessionRepo = createInMemorySessionRepository()
  return {
    repo,
    tokenRepo,
    sessionRepo,
    svc: createUserService({ repo, tokenRepo, sessionRepo }),
  }
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

Deno.test('update persists OIDC profile fields; email_verified is NOT client-settable', async () => {
  const { repo, svc } = service(createInMemoryUserRepository())
  const now = new Date()
  await repo.create({
    id: 'u1',
    email: 'a@b.com',
    passwordHash: 'h',
    createdAt: now,
    updatedAt: now,
  })
  await svc.update('u1', { name: 'Ada L', given_name: 'Ada', family_name: 'L' })
  const rec = await repo.findById('u1')
  assertEquals(rec?.name, 'Ada L')
  assertEquals(rec?.givenName, 'Ada')
  // email_verified is internal-only: settable via the repo, never the client update schema
  await repo.update('u1', { emailVerified: true })
  assertEquals((await repo.findById('u1'))?.emailVerified, true)
})

Deno.test('updateUserSchema strips email_verified (not client-settable)', () => {
  const parsed = updateUserSchema.parse({ name: 'X', email_verified: true })
  assertEquals('email_verified' in parsed, false)
})

Deno.test("changing the password revokes the user's refresh tokens and sessions", async () => {
  const { repo, svc, tokenRepo, sessionRepo } = service(
    createInMemoryUserRepository(),
  )
  const now = new Date()
  const later = new Date(Date.now() + 60_000)
  for (const id of ['u1', 'u2']) {
    await repo.create({
      id,
      email: `${id}@b.com`,
      passwordHash: 'h',
      createdAt: now,
      updatedAt: now,
    })
    await tokenRepo.create({
      id: `rt-${id}`,
      userId: id,
      appServiceId: 's1',
      tokenHash: `rt-hash-${id}`,
      expiresAt: later,
    })
    await sessionRepo.create({
      id: `se-${id}`,
      userId: id,
      tokenHash: `se-hash-${id}`,
      expiresAt: later,
    })
  }

  await svc.update('u1', { password: 'newpw12345' })

  assertEquals(!!(await tokenRepo.findByHash('rt-hash-u1'))?.revokedAt, true)
  assertEquals(await sessionRepo.findActiveByTokenHash('se-hash-u1'), null)
  // Only that user's credentials: other users are untouched.
  assertEquals(!!(await tokenRepo.findByHash('rt-hash-u2'))?.revokedAt, false)
  assertEquals(
    (await sessionRepo.findActiveByTokenHash('se-hash-u2'))?.id,
    'se-u2',
  )
})

Deno.test('updating a non-password field leaves credentials alone', async () => {
  const { repo, svc, tokenRepo } = service(createInMemoryUserRepository())
  const now = new Date()
  await repo.create({
    id: 'u1',
    email: 'a@b.com',
    passwordHash: 'h',
    createdAt: now,
    updatedAt: now,
  })
  await tokenRepo.create({
    id: 'rt1',
    userId: 'u1',
    appServiceId: 's1',
    tokenHash: 'rt-hash',
    expiresAt: new Date(Date.now() + 60_000),
  })
  await svc.update('u1', { name: 'Ada' })
  assertEquals(!!(await tokenRepo.findByHash('rt-hash'))?.revokedAt, false)
})

Deno.test('updateUserSchema accepts only http(s) picture URLs', () => {
  for (
    const ok of [
      'https://lh3.googleusercontent.com/a/ACg8ocK=s96-c',
      'http://localhost:3000/avatar.png',
    ]
  ) {
    assertEquals(updateUserSchema.safeParse({ picture: ok }).success, true)
  }
  for (
    const bad of [
      'javascript:alert(1)',
      'JavaScript:alert(1)',
      'data:image/svg+xml;base64,AAAA',
      'not a url',
    ]
  ) {
    assertEquals(updateUserSchema.safeParse({ picture: bad }).success, false)
  }
})

Deno.test('changing email resets emailVerified to false', async () => {
  const { repo, svc } = service(createInMemoryUserRepository())
  const now = new Date()
  await repo.create({
    id: 'u1',
    email: 'a@b.com',
    passwordHash: 'h',
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  })
  await svc.update('u1', { email: 'new@b.com' })
  assertEquals((await repo.findById('u1'))?.emailVerified, false)
})
