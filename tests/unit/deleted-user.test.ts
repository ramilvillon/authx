import { assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps, seedDefaultService } from '../helpers.ts'

// Deleting a user removes only the users row: its refresh tokens, sessions and
// social links survive. None of them may still authenticate or mint tokens.
Deno.test('a deleted user cannot refresh, resume a session, or log in via Google', async () => {
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

  await userService.remove(user.id)

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
      }, audience),
    Error,
    'invalid grant',
  )
})
