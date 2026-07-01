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
import type { SocialAccountRepository } from '../../src/modules/auth/social.repository.ts'
import { loadConfig } from '../../src/config.ts'
import { generateRsaKeyPairPem, loadKeySet } from '../../src/lib/keys.ts'

const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
const keySet = await loadKeySet(privateKeyPem, publicKeyPem)

function setup() {
  const config = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: privateKeyPem,
    JWT_PUBLIC_KEY: publicKeyPem,
    JWT_ISSUER: 'http://localhost:3000',
  })
  const userRepo = createInMemoryUserRepository({ user: [] })
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const orgRepo = createInMemoryOrgRepository()
  const rbacRepo = createInMemoryRbacRepository()
  const socialRepo: SocialAccountRepository = {
    findByProviderAccount: () => Promise.resolve(null),
    link: () => Promise.resolve(),
  }
  const userService = createUserService({ repo: userRepo })
  const authService = createAuthService({
    userRepo,
    tokenRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    config,
    keySet,
    sessionRepo: createInMemorySessionRepository(),
    authCodeRepo: createInMemoryAuthCodeRepository(),
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

Deno.test('reusing a rotated refresh token revokes the whole family', async () => {
  const { authService, userService, orgRepo } = setup()
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
