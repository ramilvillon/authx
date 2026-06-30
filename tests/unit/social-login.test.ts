import { assert, assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'

Deno.test('loginWithGoogle creates + links a new user, issues tokens', async () => {
  const { deps, userRepo } = makeTestDeps()
  const pair = await deps.authService.loginWithGoogle({
    providerAccountId: 'g-123',
    email: 'g@b.com',
    emailVerified: true,
  })
  assert(pair.access_token.length > 0)
  const user = await userRepo.findByEmail('g@b.com')
  assertEquals(user?.passwordHash, null)
})

Deno.test('loginWithGoogle is idempotent for the same google account', async () => {
  const { deps, userRepo } = makeTestDeps()
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
