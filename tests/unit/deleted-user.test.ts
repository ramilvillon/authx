import { assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps, seedDefaultService } from '../helpers.ts'

// userService.remove now purges these rows outright (see users-service.test.ts).
// This is the F13 invariant underneath that, and it is deliberately tested a
// different way: an orphan is created by deleting the users row DIRECTLY,
// bypassing the cascade. Orphans can still arrive from a half-finished purge,
// a manual DB delete, or rows predating the cascade — and none of them may
// authenticate or mint tokens. Defence in depth, not a duplicate.
Deno.test('an orphaned row cannot refresh, resume a session, or log in via Google', async () => {
  const ctx = makeTestDeps()
  const { authService, userService } = ctx.deps
  const user = await userService.register({
    email: 'gone@b.com',
    password: 'pw123456',
  })
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const pair = await authService.passwordGrant(
    'gone@b.com',
    'pw123456',
    audience,
  )
  const session = await authService.loginCreateSession('gone@b.com', 'pw123456')
  await ctx.socialRepo.link({
    id: crypto.randomUUID(),
    userId: user.id,
    provider: 'google',
    providerAccountId: 'g1',
  })

  // NOT userService.remove: that would purge the very rows under test.
  await ctx.userRepo.delete(user.id)

  await assertRejects(
    () => authService.refreshGrant(pair.refresh_token),
    Error,
    'invalid refresh token',
  )
  assertEquals(await authService.userIdForSession(session.token), null)
  assertEquals(await authService.resolveSession(session.token), null)
  await assertRejects(
    () =>
      authService.loginWithGoogle({
        providerAccountId: 'g1',
        email: 'gone@b.com',
        emailVerified: true,
      }),
    Error,
    'invalid grant',
  )
})
