import { assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps, seedDefaultService } from '../helpers.ts'

const days = (n: number) => n * 86400 * 1000

Deno.test('removing a user marks the row deleted instead of destroying it', async () => {
  const ctx = makeTestDeps()
  const user = await ctx.deps.userService.register({
    email: 'gone@b.com',
    password: 'pw123456',
  })

  await ctx.deps.userService.remove(user.id)

  // Gone as far as every ordinary lookup is concerned...
  assertEquals(await ctx.userRepo.findById(user.id), null)
  assertEquals(await ctx.userRepo.findByEmail('gone@b.com'), null)
  // ...but still recoverable until the grace period ends. An account deletion
  // an attacker can trigger should not be irreversible.
  assertEquals(
    (await ctx.userRepo.findDeletedBefore(new Date(Date.now() + 1000))).length,
    1,
  )
})

Deno.test('a soft-deleted user cannot log in, refresh, or resume a session', async () => {
  const ctx = makeTestDeps()
  const { authService, userService } = ctx.deps
  const user = await userService.register({
    email: 'gone2@b.com',
    password: 'pw123456',
  })
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const pair = await authService.passwordGrant(
    'gone2@b.com',
    'pw123456',
    audience,
  )
  const session = await authService.loginCreateSession(
    'gone2@b.com',
    'pw123456',
  )

  await userService.remove(user.id)

  // The repository filter is the single chokepoint: every one of these reaches
  // the user through findById/findByEmail, so none of them needs its own check.
  await assertRejects(
    () => authService.passwordGrant('gone2@b.com', 'pw123456', audience),
    Error,
    'invalid credentials',
  )
  await assertRejects(
    () => authService.refreshGrant(pair.refresh_token),
    Error,
    'invalid refresh token',
  )
  assertEquals(await authService.resolveSession(session.token), null)
})

Deno.test('the address stays reserved while a deleted account is recoverable', async () => {
  const ctx = makeTestDeps()
  const user = await ctx.deps.userService.register({
    email: 'taken@b.com',
    password: 'pw123456',
  })
  await ctx.deps.userService.remove(user.id)

  // users.email is UNIQUE, so the row still occupies the address. Registration
  // must say so plainly rather than hit a duplicate-key error at the database.
  await assertRejects(
    () =>
      ctx.deps.userService.register({
        email: 'taken@b.com',
        password: 'pw123456',
      }),
    Error,
    'email already registered',
  )
})

Deno.test('purging after the grace period hard-deletes and cascades', async () => {
  const ctx = makeTestDeps()
  const user = await ctx.deps.userService.register({
    email: 'purge@b.com',
    password: 'pw123456',
  })
  await ctx.socialRepo.link({
    id: crypto.randomUUID(),
    userId: user.id,
    provider: 'google',
    providerAccountId: 'g-purge',
  })
  await ctx.deps.userService.remove(user.id)

  // Still inside the grace period: nothing is destroyed yet.
  assertEquals(
    await ctx.deps.userService.purgeDeletedBefore(
      new Date(Date.now() - days(30)),
    ),
    0,
  )
  assertEquals(
    (await ctx.userRepo.findDeletedBefore(new Date(Date.now() + 1000))).length,
    1,
  )

  assertEquals(
    await ctx.deps.userService.purgeDeletedBefore(new Date(Date.now() + 1000)),
    1,
  )
  assertEquals(
    (await ctx.userRepo.findDeletedBefore(new Date(Date.now() + 1000))).length,
    0,
  )
  assertEquals(
    await ctx.socialRepo.findByProviderAccount('google', 'g-purge'),
    null,
    'the purge must run the same cascade a hard delete did',
  )
})
