import { createInMemoryVerificationTokenRepository } from '../../src/modules/verification/verification.repository.ts'
import { assert, assertEquals, assertRejects } from '@std/assert'
import { decode } from 'hono/jwt'
import { createInMemoryUserRepository } from '../../src/modules/users/users.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../../src/modules/auth/token.repository.ts'
import { createInMemoryOrgRepository } from '../../src/modules/orgs/orgs.repository.ts'
import { createInMemoryRbacRepository } from '../../src/modules/rbac/rbac.repository.ts'
import { createInMemorySessionRepository } from '../../src/modules/auth/session.repository.ts'
import { createInMemoryAuthCodeRepository } from '../../src/modules/auth/authcode.repository.ts'
import { createUserService } from '../../src/modules/users/users.service.ts'
import { createAuthService } from '../../src/modules/auth/auth.service.ts'
import { createInMemorySocialAccountRepository } from '../../src/modules/auth/social.repository.ts'
import { createInMemoryTotpRepository } from '../../src/modules/mfa/totp.repository.ts'
import { createTotpService } from '../../src/modules/mfa/totp.service.ts'
import { createInMemoryPasskeyRepository } from '../../src/modules/passkeys/passkey.repository.ts'
import { loadConfig } from '../../src/config.ts'
import { generateRsaKeyPairPem, loadKeyRing } from '../../src/lib/keys.ts'
import type { Logger } from '../../src/lib/logger.ts'

const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
const keySet = await loadKeyRing(privateKeyPem, publicKeyPem, [])

// A stand-in for pino's Logger -- these tests never assert on log output.
const testLogger = { error: () => {} } as unknown as Logger

function setup(opts: {
  env?: Record<string, string>
  totp?: Parameters<typeof createAuthService>[0]['totp']
} = {}) {
  const config = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: privateKeyPem,
    JWT_PUBLIC_KEY: publicKeyPem,
    JWT_ISSUER: 'http://localhost:3000',
    ALLOW_PASSWORD_GRANT: 'true',
    ...opts.env,
  })
  const userRepo = createInMemoryUserRepository({ user: [] })
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const orgRepo = createInMemoryOrgRepository()
  const rbacRepo = createInMemoryRbacRepository()
  const socialRepo = createInMemorySocialAccountRepository()
  const sessionRepo = createInMemorySessionRepository()
  const userService = createUserService({
    repo: userRepo,
    tokenRepo,
    sessionRepo,
    authCodeRepo: createInMemoryAuthCodeRepository(),
    verificationRepo: createInMemoryVerificationTokenRepository(),
    socialRepo: createInMemorySocialAccountRepository(),
    orgRepo,
    totpRepo: createInMemoryTotpRepository(),
    passkeyRepo: createInMemoryPasskeyRepository(),
    allowPasswordGrant: true,
  })
  const authService = createAuthService({
    userRepo,
    tokenRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    config,
    keySet,
    sessionRepo,
    authCodeRepo: createInMemoryAuthCodeRepository(),
    logger: testLogger,
    totp: opts.totp ?? createTotpService({
      totpRepo: createInMemoryTotpRepository(),
      userRepo,
      issuer: config.issuer,
      encryptionKey: '',
    }),
  })
  return { authService, userService, orgRepo, rbacRepo }
}

// Seeds a minimal org + service + membership, returns audience.
async function seedService(
  orgRepo: ReturnType<typeof createInMemoryOrgRepository>,
  userId: string,
  audience = 'test-aud',
): Promise<string> {
  const now = new Date()
  const org = await orgRepo.createOrg({
    id: 'o1',
    slug: 'test',
    name: 'Test',
    createdAt: now,
  })
  await orgRepo.createService({
    id: 's1',
    orgId: 'o1',
    clientId: 'cid',
    clientSecretHash: null,
    name: 'App',
    slug: 'app',
    audience,
    type: 'public',
    redirectUris: [],
    createdAt: now,
  })
  await orgRepo.addMember({ id: 'm1', userId, orgId: org.id, createdAt: now })
  return audience
}

Deno.test('password grant returns a token pair', async () => {
  const { authService, userService, orgRepo } = setup()
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id)
  const pair = await authService.passwordGrant('a@b.com', 'pw123456', audience)
  assert(pair.access_token.length > 0)
  assertEquals(pair.token_type, 'Bearer')
})

Deno.test('password grant rejects bad credentials', async () => {
  const { authService, userService } = setup()
  await userService.register({ email: 'a@b.com', password: 'pw123456' })
  await assertRejects(
    () => authService.passwordGrant('a@b.com', 'wrong', 'any-aud'),
    Error,
    'invalid credentials',
  )
})

Deno.test('refresh grant rotates the refresh token', async () => {
  const { authService, userService, orgRepo } = setup()
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id)
  const first = await authService.passwordGrant('a@b.com', 'pw123456', audience)
  const second = await authService.refreshGrant(first.refresh_token)
  assert(second.refresh_token !== first.refresh_token)
})

Deno.test('refresh grant stops working once the user is removed from the org', async () => {
  const { authService, userService, orgRepo } = setup()
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id)
  const first = await authService.passwordGrant('a@b.com', 'pw123456', audience)

  await orgRepo.removeMember(user.id, 'o1')

  await assertRejects(
    () => authService.refreshGrant(first.refresh_token),
    Error,
    'not a member of this organization',
  )
})

Deno.test('reusing a rotated refresh token revokes the whole family', async () => {
  const { authService, userService, orgRepo } = setup({
    env: { REFRESH_TOKEN_REUSE_GRACE: '0' },
  })
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id)
  const first = await authService.passwordGrant('a@b.com', 'pw123456', audience)
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

Deno.test('replaying a just-rotated refresh token is refused but keeps the family', async () => {
  // Two tabs refreshing at once: the loser must not sign everyone out.
  const { authService, userService, orgRepo } = setup()
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id)
  const first = await authService.passwordGrant('a@b.com', 'pw123456', audience)
  const second = await authService.refreshGrant(first.refresh_token)

  await assertRejects(
    () => authService.refreshGrant(first.refresh_token),
    Error,
    'invalid refresh token',
  )
  assert((await authService.refreshGrant(second.refresh_token)).access_token)
})

Deno.test('replaying an explicitly revoked refresh token is never graced', async () => {
  const { authService, userService, orgRepo } = setup()
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id)
  const a = await authService.passwordGrant('a@b.com', 'pw123456', audience)
  const b = await authService.passwordGrant('a@b.com', 'pw123456', audience)
  await authService.revoke(a.refresh_token)

  await assertRejects(
    () => authService.refreshGrant(a.refresh_token),
    Error,
    'reuse detected',
  )
  await assertRejects(
    () => authService.refreshGrant(b.refresh_token),
    Error,
    'reuse detected',
  )
})

Deno.test('password grant token carries correct aud and scope', async () => {
  const { authService, userService, orgRepo, rbacRepo } = setup()
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  const audience = await seedService(orgRepo, user.id, 'acme-billing')
  // Give the user a billing:read permission via per-service RBAC.
  const role = await rbacRepo.createRole({
    id: 'r1',
    appServiceId: 's1',
    name: 'billing-viewer',
  })
  const perm = await rbacRepo.createPermission({
    id: 'p1',
    appServiceId: 's1',
    key: 'billing:read',
  })
  await rbacRepo.grantPermissionToRole(role.id, perm.id)
  await rbacRepo.assignRoleToUser(user.id, role.id)

  const pair = await authService.passwordGrant('a@b.com', 'pw123456', audience)
  const { payload } = decode(pair.access_token)
  assertEquals(payload.aud, 'acme-billing')
  assertEquals(payload.scope, 'billing:read')
})

// isLocked -> await verify -> recordFailure let a parallel burst all pass the
// lock check before any failure was counted. Each attempt must be counted
// before the await.
Deno.test('parallel code guesses cannot exceed LOGIN_MAX_FAILURES', async () => {
  let verifyCalls = 0
  const { authService, userService } = setup({
    env: { LOGIN_MAX_FAILURES: '3' },
    totp: {
      isEnabled: () => Promise.resolve(true),
      verify: async (_userId: string, code: string) => {
        verifyCalls++
        await new Promise((r) => setTimeout(r, 5))
        return code === '123456'
      },
    },
  })
  const user = await userService.register({
    email: 'race@b.com',
    password: 'pw123456',
  })
  await Promise.allSettled(
    Array.from(
      { length: 10 },
      () => authService.completeMfaLogin(user.id, 'wrong'),
    ),
  )
  assert(verifyCalls <= 3, `verify ran ${verifyCalls} times`)
  // The valid code is refused by the lock, before verify even runs.
  const before = verifyCalls
  await assertRejects(
    () => authService.completeMfaLogin(user.id, '123456'),
    Error,
    'invalid credentials',
  )
  assertEquals(verifyCalls, before)
})
