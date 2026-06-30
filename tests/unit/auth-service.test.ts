import { assert, assertEquals, assertRejects } from '@std/assert'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../../src/modules/auth/token.repository.ts'
import { createUserService } from '../../src/modules/users/users.service.ts'
import { createAuthService } from '../../src/modules/auth/auth.service.ts'
import type { SocialAccountRepository } from '../../src/modules/auth/social.repository.ts'
import { loadConfig } from '../../src/config.ts'

function setup() {
  const config = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_SECRET: 'sec',
  })
  const userRepo = createInMemoryUserRepository({ user: [] })
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const socialRepo: SocialAccountRepository = {
    findByProviderAccount: () => Promise.resolve(null),
    link: () => Promise.resolve(),
  }
  const userService = createUserService({ repo: userRepo })
  const authService = createAuthService({
    userRepo,
    tokenRepo,
    socialRepo,
    config,
  })
  return { authService, userService }
}

Deno.test('password grant returns a token pair', async () => {
  const { authService, userService } = setup()
  await userService.register({ email: 'a@b.com', password: 'pw123456' })
  const pair = await authService.passwordGrant('a@b.com', 'pw123456')
  assert(pair.access_token.length > 0)
  assertEquals(pair.token_type, 'Bearer')
})

Deno.test('password grant rejects bad credentials', async () => {
  const { authService, userService } = setup()
  await userService.register({ email: 'a@b.com', password: 'pw123456' })
  await assertRejects(
    () => authService.passwordGrant('a@b.com', 'wrong'),
    Error,
    'invalid credentials',
  )
})

Deno.test('refresh grant rotates the refresh token', async () => {
  const { authService, userService } = setup()
  await userService.register({ email: 'a@b.com', password: 'pw123456' })
  const first = await authService.passwordGrant('a@b.com', 'pw123456')
  const second = await authService.refreshGrant(first.refresh_token)
  assert(second.refresh_token !== first.refresh_token)
})

Deno.test('reusing a rotated refresh token revokes the whole family', async () => {
  const { authService, userService } = setup()
  await userService.register({ email: 'a@b.com', password: 'pw123456' })
  const first = await authService.passwordGrant('a@b.com', 'pw123456')
  const second = await authService.refreshGrant(first.refresh_token)

  // Replaying the old (rotated) token is detected as theft.
  await assertRejects(
    () => authService.refreshGrant(first.refresh_token),
    Error,
    'reuse detected',
  )
  // ...and the family is revoked, so the previously-valid token is dead too.
  await assertRejects(
    () => authService.refreshGrant(second.refresh_token),
    Error,
    'reuse detected',
  )
})
