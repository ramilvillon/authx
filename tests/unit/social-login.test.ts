import { assert, assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps, seedDefaultService } from '../helpers.ts'

Deno.test('loginWithGoogle new user: creates user + links account, throws unknown audience when no service seeded', async () => {
  const { deps, userRepo } = makeTestDeps()
  // No service seeded → issueTokensForService throws "unknown audience".
  // Side-effects (user created, social linked) happen before the throw.
  await assertRejects(
    () =>
      deps.authService.loginWithGoogle({
        providerAccountId: 'g-123',
        email: 'g@b.com',
        emailVerified: true,
      }, 'test-app'),
    Error,
    'unknown audience',
  )
  const user = await userRepo.findByEmail('g@b.com')
  assertEquals(user?.passwordHash, null)
})

Deno.test('loginWithGoogle links and issues tokens for a passwordless invited user who is a member', async () => {
  const { deps, userRepo, orgRepo } = makeTestDeps()
  const now = new Date()
  // Simulate an invite-created user (no password).
  const invited = await userRepo.create({
    id: crypto.randomUUID(),
    email: 'invited@b.com',
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(orgRepo, invited.id)
  const pair = await deps.authService.loginWithGoogle({
    providerAccountId: 'g-222',
    email: 'invited@b.com',
    emailVerified: true,
  }, audience)
  assert(pair.access_token.length > 0)
})

Deno.test('loginWithGoogle is idempotent for the same google account', async () => {
  const { deps, userRepo, orgRepo } = makeTestDeps()
  const now = new Date()
  // Pre-create a passwordless user and add them to an org.
  const invited = await userRepo.create({
    id: crypto.randomUUID(),
    email: 'g@b.com',
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(orgRepo, invited.id)
  await deps.authService.loginWithGoogle({
    providerAccountId: 'g-1',
    email: 'g@b.com',
    emailVerified: true,
  }, audience)
  await deps.authService.loginWithGoogle({
    providerAccountId: 'g-1',
    email: 'g@b.com',
    emailVerified: true,
  }, audience)
  const all = await userRepo.list()
  assertEquals(all.filter((u) => u.email === 'g@b.com').length, 1)
})

Deno.test('loginWithGoogle refuses an unverified email', async () => {
  const { deps } = makeTestDeps()
  await assertRejects(
    () =>
      deps.authService.loginWithGoogle({
        providerAccountId: 'g-x',
        email: 'evil@b.com',
        emailVerified: false,
      }, 'test-app'),
    Error,
    'not verified',
  )
})

Deno.test('loginWithGoogle refuses to link when local account has a password (pre-hijacking guard)', async () => {
  const { deps, userRepo, socialRepo } = makeTestDeps()
  // Register a normal password-based user.
  const userService = {
    register: async (input: { email: string; password: string }) => {
      const { hashPassword } = await import('../../src/lib/password.ts')
      const now = new Date()
      const user = await userRepo.create({
        id: crypto.randomUUID(),
        email: input.email,
        passwordHash: await hashPassword(input.password),
        createdAt: now,
        updatedAt: now,
      })
      return user
    },
  }
  await userService.register({ email: 'alice@b.com', password: 'secret123' })

  await assertRejects(
    () =>
      deps.authService.loginWithGoogle({
        providerAccountId: 'g-attacker',
        email: 'alice@b.com',
        emailVerified: true,
      }, 'test-app'),
    Error,
    'already exists',
  )
  // Verify no social account was linked.
  const linked = await socialRepo.findByProviderAccount('google', 'g-attacker')
  assertEquals(linked, null)
})
