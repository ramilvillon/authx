import { assert, assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'

Deno.test('loginWithGoogle new user: creates a passwordless user, links the account, opens a session', async () => {
  const { deps, userRepo, socialRepo } = makeTestDeps()
  const login = await deps.authService.loginWithGoogle({
    providerAccountId: 'g-123',
    email: 'g@b.com',
    emailVerified: true,
  })
  const user = await userRepo.findByEmail('g@b.com')
  assertEquals(user?.passwordHash, null)
  assertEquals(login.userId, user?.id)
  assertEquals(
    (await socialRepo.findByProviderAccount('google', 'g-123'))?.userId,
    user?.id,
  )
  assertEquals(await deps.authService.userIdForSession(login.token), user?.id)
})

Deno.test('loginWithGoogle links a passwordless, verified account and signs it in', async () => {
  const { deps, userRepo, socialRepo } = makeTestDeps()
  const now = new Date()
  // Simulate an invite-created user (no password) who verified their email.
  const invited = await userRepo.create({
    id: crypto.randomUUID(),
    email: 'invited@b.com',
    passwordHash: null,
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  })
  const login = await deps.authService.loginWithGoogle({
    providerAccountId: 'g-222',
    email: 'invited@b.com',
    emailVerified: true,
  })
  assertEquals(login.userId, invited.id)
  assert(await socialRepo.findByProviderAccount('google', 'g-222'))
})

Deno.test('loginWithGoogle is idempotent for the same google account', async () => {
  const { deps, userRepo } = makeTestDeps()
  const now = new Date()
  // Pre-create a passwordless, verified user and add them to an org.
  await userRepo.create({
    id: crypto.randomUUID(),
    email: 'g@b.com',
    passwordHash: null,
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  })
  await deps.authService.loginWithGoogle({
    providerAccountId: 'g-1',
    email: 'g@b.com',
    emailVerified: true,
  })
  await deps.authService.loginWithGoogle({
    providerAccountId: 'g-1',
    email: 'g@b.com',
    emailVerified: true,
  })
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
      }),
    Error,
    'not verified',
  )
})

Deno.test('loginWithGoogle refuses to link a passwordless account whose email is unverified', async () => {
  const { deps, userRepo, socialRepo } = makeTestDeps()
  const now = new Date()
  // Attacker pre-seeds an unverified account on the victim's address; the
  // victim's Google login must not adopt it.
  await userRepo.create({
    id: crypto.randomUUID(),
    email: 'victim@b.com',
    passwordHash: null,
    emailVerified: false,
    createdAt: now,
    updatedAt: now,
  })
  await assertRejects(
    () =>
      deps.authService.loginWithGoogle({
        providerAccountId: 'g-attacker-2',
        email: 'victim@b.com',
        emailVerified: true,
      }),
    Error,
    'already exists',
  )
  assertEquals(
    await socialRepo.findByProviderAccount('google', 'g-attacker-2'),
    null,
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
      }),
    Error,
    'already exists',
  )
  // Verify no social account was linked.
  const linked = await socialRepo.findByProviderAccount('google', 'g-attacker')
  assertEquals(linked, null)
})
