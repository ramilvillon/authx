import { createInMemoryOrgRepository } from '../../src/modules/orgs/orgs.repository.ts'
import { assertEquals, assertRejects } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'
import { createUserService } from '../../src/modules/users/users.service.ts'
import { updateUserSchema } from '../../src/modules/users/users.schema.ts'
import { verifyPassword } from '../../src/lib/password.ts'
import { createInMemoryRefreshTokenRepository } from '../../src/modules/auth/token.repository.ts'
import { createInMemorySessionRepository } from '../../src/modules/auth/session.repository.ts'
import { createInMemoryAuthCodeRepository } from '../../src/modules/auth/authcode.repository.ts'
import { createInMemoryVerificationTokenRepository } from '../../src/modules/verification/verification.repository.ts'
import { createInMemorySocialAccountRepository } from '../../src/modules/auth/social.repository.ts'

// Every repository that holds rows keyed by user id, so a delete can be checked
// against all of them at once.
function fullService() {
  const repo = createInMemoryUserRepository({ user: [] })
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const sessionRepo = createInMemorySessionRepository()
  const authCodeRepo = createInMemoryAuthCodeRepository()
  const verificationRepo = createInMemoryVerificationTokenRepository()
  const socialRepo = createInMemorySocialAccountRepository()
  const orgRepo = createInMemoryOrgRepository()
  return {
    repo,
    orgRepo,
    tokenRepo,
    sessionRepo,
    authCodeRepo,
    verificationRepo,
    socialRepo,
    svc: createUserService({
      repo,
      tokenRepo,
      sessionRepo,
      authCodeRepo,
      verificationRepo,
      socialRepo,
      orgRepo,
      allowPasswordGrant: true,
    }),
  }
}

function service(repo = createInMemoryUserRepository({ user: [] })) {
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const sessionRepo = createInMemorySessionRepository()
  return {
    repo,
    tokenRepo,
    sessionRepo,
    svc: createUserService({
      repo,
      tokenRepo,
      sessionRepo,
      authCodeRepo: createInMemoryAuthCodeRepository(),
      verificationRepo: createInMemoryVerificationTokenRepository(),
      socialRepo: createInMemorySocialAccountRepository(),
      orgRepo: createInMemoryOrgRepository(),
      allowPasswordGrant: true,
    }),
  }
}

Deno.test('register hashes the password and grants no roles', async () => {
  const { repo, svc } = service()
  const user = await svc.register({ email: 'a@b.com', password: 'pw123456' })
  assertEquals(user.email, 'a@b.com')
  const stored = await repo.findById(user.id)
  assertEquals(await verifyPassword('pw123456', stored!.passwordHash!), true)
  // Roles are per-service and granted through the management API. The old
  // global 'user' role granted nothing and was never seeded, so the drizzle
  // repository threw on it -- see registration.drizzle.test.ts.
  const access = await repo.findWithAccessById(user.id)
  assertEquals(access?.roles, [])
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
  await svc.update(
    'u1',
    { name: 'Ada L', given_name: 'Ada', family_name: 'L' },
    {
      requireCurrentPassword: true,
    },
  )
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

  // Operator path: the challenge is exercised in the route tests; this one is
  // about revocation, which fires the same either way.
  await svc.update('u1', { password: 'newpw12345' }, {
    requireCurrentPassword: false,
  })

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
  await svc.update('u1', { name: 'Ada' }, { requireCurrentPassword: true })
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
  // Self-service: changing an email carries no password challenge, by design —
  // revoking there would hand a stolen-token holder a mass-eviction primitive.
  await svc.update('u1', { email: 'new@b.com' }, {
    requireCurrentPassword: true,
  })
  assertEquals((await repo.findById('u1'))?.emailVerified, false)
})

// The cascade now runs at purge time, not at remove time: remove only marks the
// row deleted (see soft-delete.test.ts). Same guarantee, later moment.
Deno.test('purging a deleted user removes every row that referenced them', async () => {
  const ctx = fullService()
  const now = new Date()
  const later = new Date(Date.now() + 60_000)
  const user = await ctx.svc.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const other = await ctx.svc.register({
    email: 'b@b.com',
    password: 'pw123456',
  })

  for (const id of [user.id, other.id]) {
    await ctx.tokenRepo.create({
      id: `rt-${id}`,
      userId: id,
      appServiceId: 's1',
      tokenHash: `rt-hash-${id}`,
      expiresAt: later,
    })
    await ctx.sessionRepo.create({
      id: `se-${id}`,
      userId: id,
      tokenHash: `se-hash-${id}`,
      expiresAt: later,
    })
    await ctx.authCodeRepo.create({
      id: `ac-${id}`,
      userId: id,
      appServiceId: 's1',
      codeHash: `ac-hash-${id}`,
      redirectUri: 'https://app.example/cb',
      scope: '',
      codeChallenge: 'c',
      codeChallengeMethod: 'S256',
      nonce: null,
      expiresAt: later,
      authTime: now,
    })
    await ctx.verificationRepo.create({
      id: `ev-${id}`,
      userId: id,
      email: 'x@b.com',
      purpose: 'verify_email',
      tokenHash: `ev-hash-${id}`,
      expiresAt: later,
    })
    await ctx.socialRepo.link({
      id: `sa-${id}`,
      userId: id,
      provider: 'google',
      providerAccountId: `g-${id}`,
    })
  }

  await ctx.svc.remove(user.id)
  assertEquals(await ctx.svc.purgeDeletedBefore(new Date(Date.now() + 1000)), 1)

  // The schema has no foreign keys, so nothing cleans these up for us.
  assertEquals(await ctx.tokenRepo.findByHash(`rt-hash-${user.id}`), null)
  assertEquals(
    await ctx.sessionRepo.findActiveByTokenHash(`se-hash-${user.id}`),
    null,
  )
  assertEquals(
    await ctx.authCodeRepo.findByCodeHash(`ac-hash-${user.id}`),
    null,
  )
  assertEquals(
    await ctx.verificationRepo.findByHash(`ev-hash-${user.id}`),
    null,
  )
  assertEquals(
    await ctx.socialRepo.findByProviderAccount('google', `g-${user.id}`),
    null,
  )
  assertEquals(
    (await ctx.repo.findWithAccessById(user.id))?.roles ?? null,
    null,
  )

  // Only that user's rows: the other account is untouched.
  assertEquals(!!(await ctx.tokenRepo.findByHash(`rt-hash-${other.id}`)), true)
  assertEquals(
    !!(await ctx.sessionRepo.findActiveByTokenHash(`se-hash-${other.id}`)),
    true,
  )
  assertEquals(
    !!(await ctx.authCodeRepo.findByCodeHash(`ac-hash-${other.id}`)),
    true,
  )
  assertEquals(
    !!(await ctx.verificationRepo.findByHash(`ev-hash-${other.id}`)),
    true,
  )
  assertEquals(
    !!(await ctx.socialRepo.findByProviderAccount('google', `g-${other.id}`)),
    true,
  )
})

Deno.test('purging a deleted user removes their org memberships too', async () => {
  const ctx = fullService()
  const user = await ctx.svc.register({
    email: 'm@b.com',
    password: 'pw123456',
  })
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: 'acme',
    name: 'Acme',
    createdAt: new Date(),
  })
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: user.id,
    orgId: org.id,
    createdAt: new Date(),
  })
  assertEquals(await ctx.orgRepo.isMember(user.id, org.id), true)

  await ctx.svc.remove(user.id)
  await ctx.svc.purgeDeletedBefore(new Date(Date.now() + 1000))

  // A surviving membership would be inherited by any future row reusing the id.
  assertEquals(await ctx.orgRepo.isMember(user.id, org.id), false)
})
