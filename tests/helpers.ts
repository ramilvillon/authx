import type { Deps } from '../src/deps.ts'
import { testDb } from './mysql-mode.ts'
import { createDrizzleUserRepository } from '../src/modules/users/users.repository.drizzle.ts'
import { createDrizzleRefreshTokenRepository } from '../src/modules/auth/token.repository.drizzle.ts'
import { createDrizzleSocialAccountRepository } from '../src/modules/auth/social.repository.drizzle.ts'
import { createDrizzleOrgRepository } from '../src/modules/orgs/orgs.repository.drizzle.ts'
import { createDrizzleRbacRepository } from '../src/modules/rbac/rbac.repository.drizzle.ts'
import { createDrizzleSessionRepository } from '../src/modules/auth/session.repository.drizzle.ts'
import { createDrizzleAuthCodeRepository } from '../src/modules/auth/authcode.repository.drizzle.ts'
import { createDrizzleVerificationTokenRepository } from '../src/modules/verification/verification.repository.drizzle.ts'
import type { UserRepository } from '../src/modules/users/users.repository.ts'
import { createApp } from '../src/app.ts'
import { loadConfig } from '../src/config.ts'
import { createInMemoryUserRepository } from '../src/modules/users/users.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../src/modules/auth/token.repository.ts'
import { createInMemoryOrgRepository } from '../src/modules/orgs/orgs.repository.ts'
import { createInMemoryRbacRepository } from '../src/modules/rbac/rbac.repository.ts'
import { createInMemorySessionRepository } from '../src/modules/auth/session.repository.ts'
import { createInMemoryAuthCodeRepository } from '../src/modules/auth/authcode.repository.ts'
import { createInMemoryVerificationTokenRepository } from '../src/modules/verification/verification.repository.ts'
import { createVerificationService } from '../src/modules/verification/verification.service.ts'
import { createUserService } from '../src/modules/users/users.service.ts'
import { createAuthService } from '../src/modules/auth/auth.service.ts'
import { createAdminService } from '../src/modules/admin/admin.service.ts'
import { createMemoryRateLimitStore } from '../src/lib/rate-limit-store.ts'
import {
  createInMemorySocialAccountRepository,
  type SocialAccountRepository,
} from '../src/modules/auth/social.repository.ts'
import type { TokenPurpose } from '../src/modules/verification/verification.repository.ts'
import type { OrgRepository } from '../src/modules/orgs/orgs.repository.ts'
import type { RbacRepository } from '../src/modules/rbac/rbac.repository.ts'
import { generateRsaKeyPairPem, loadKeyRing } from '../src/lib/keys.ts'
import { signAccessToken } from '../src/lib/jwt.ts'

const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
export const keySet = await loadKeyRing(privateKeyPem, publicKeyPem, [])

const testEnv = {
  DB_USER: 'app',
  DB_PASS: 'app',
  DB_NAME: 'app',
  JWT_PRIVATE_KEY: privateKeyPem,
  JWT_PUBLIC_KEY: publicKeyPem,
  JWT_ISSUER: 'http://test.local',
  LOG_LEVEL: 'silent',
}

export type TestContext = {
  deps: Deps
  userRepo: ReturnType<typeof createInMemoryUserRepository>
  tokenRepo: ReturnType<typeof createInMemoryRefreshTokenRepository>
  sessionRepo: ReturnType<typeof createInMemorySessionRepository>
  authCodeRepo: ReturnType<typeof createInMemoryAuthCodeRepository>
  verificationRepo: ReturnType<typeof createInMemoryVerificationTokenRepository>
  socialRepo: SocialAccountRepository
  orgRepo: ReturnType<typeof createInMemoryOrgRepository>
  rbacRepo: ReturnType<typeof createInMemoryRbacRepository>
  sentEmails: { to: string; purpose: TokenPurpose; link: string }[]
}

export function makeTestDeps(
  envOverrides: Record<string, string> = {},
): TestContext {
  const config = loadConfig({ ...testEnv, ...envOverrides })
  const userRepo = testDb
    ? createDrizzleUserRepository(testDb)
    : createInMemoryUserRepository()
  const tokenRepo = testDb
    ? createDrizzleRefreshTokenRepository(testDb)
    : createInMemoryRefreshTokenRepository()
  const orgRepo = testDb
    ? createDrizzleOrgRepository(testDb)
    : createInMemoryOrgRepository()
  const rbacRepo = testDb
    ? createDrizzleRbacRepository(testDb)
    : createInMemoryRbacRepository()
  const sessionRepo = testDb
    ? createDrizzleSessionRepository(testDb)
    : createInMemorySessionRepository()
  const authCodeRepo = testDb
    ? createDrizzleAuthCodeRepository(testDb)
    : createInMemoryAuthCodeRepository()
  const verificationRepo = testDb
    ? createDrizzleVerificationTokenRepository(testDb)
    : createInMemoryVerificationTokenRepository()
  const sentEmails: { to: string; purpose: TokenPurpose; link: string }[] = []
  const emailSender = {
    sendLink(to: string, purpose: TokenPurpose, link: string) {
      sentEmails.push({ to, purpose, link })
      return Promise.resolve()
    },
  }
  const verificationService = createVerificationService({
    verificationRepo,
    userRepo,
    tokenRepo,
    sessionRepo,
    emailSender,
    config,
  })
  const socialRepo = testDb
    ? createDrizzleSocialAccountRepository(testDb)
    : createInMemorySocialAccountRepository()
  const deps: Deps = {
    config,
    keySet,
    rateStore: createMemoryRateLimitStore(),
    userService: createUserService({
      repo: userRepo,
      tokenRepo,
      sessionRepo,
      authCodeRepo,
      verificationRepo,
      socialRepo,
      orgRepo,
    }),
    authService: createAuthService({
      userRepo,
      tokenRepo,
      socialRepo,
      orgRepo,
      rbacRepo,
      config,
      keySet,
      sessionRepo,
      authCodeRepo,
    }),
    adminService: createAdminService({ orgRepo, rbacRepo }),
    verificationService,
  }
  return {
    deps,
    userRepo,
    tokenRepo,
    sessionRepo,
    authCodeRepo,
    verificationRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    sentEmails,
  }
}

export function makeTestApp(envOverrides: Record<string, string> = {}) {
  const { deps, userRepo, socialRepo, orgRepo, rbacRepo, sentEmails } =
    makeTestDeps(envOverrides)
  return {
    app: createApp(deps),
    userRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    sentEmails,
  }
}

// Seeds a default org + service and adds userId as a member.
// Returns the audience string so callers can pass it to authHeader/passwordGrant.
export async function seedDefaultService(
  orgRepo: OrgRepository,
  userId: string,
  audience = 'test-service',
): Promise<string> {
  const now = new Date()
  const org = await orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: 'test',
    name: 'Test Org',
    createdAt: now,
  })
  await orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: 'cid_test',
    clientSecretHash: null,
    name: 'Test Service',
    slug: 'test-service',
    audience,
    type: 'public',
    redirectUris: [],
    createdAt: now,
  })
  await orgRepo.addMember({
    id: crypto.randomUUID(),
    userId,
    orgId: org.id,
    createdAt: now,
  })
  return audience
}

// Grants permission keys to userId within the service behind `audience`
// (creates a role + permissions, grants and assigns them) so the user's access
// token for that audience carries them as scope.
export async function grantPermissions(
  orgRepo: OrgRepository,
  rbacRepo: RbacRepository,
  audience: string,
  userId: string,
  keys: string[],
): Promise<void> {
  const service = await orgRepo.findServiceByAudience(audience)
  if (!service) throw new Error(`no service for audience ${audience}`)
  const roleId = crypto.randomUUID()
  await rbacRepo.createRole({
    id: roleId,
    appServiceId: service.id,
    name: `role-${roleId}`,
  })
  for (const key of keys) {
    const permId = crypto.randomUUID()
    await rbacRepo.createPermission({
      id: permId,
      appServiceId: service.id,
      key,
    })
    await rbacRepo.grantPermissionToRole(roleId, permId)
  }
  await rbacRepo.assignRoleToUser(userId, roleId)
}

export async function authHeader(
  app: ReturnType<typeof createApp>,
  email: string,
  password: string,
  audience: string,
) {
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'password',
      username: email,
      password,
      audience,
    }),
  })
  const body = await res.json()
  return {
    Authorization: `Bearer ${body.access_token}`,
    refresh: body.refresh_token as string,
  }
}

export const PLATFORM_PERMISSIONS = [
  'orgs:read',
  'orgs:write',
  'services:read',
  'services:write',
  'members:write',
  'rbac:write',
]

// Mints a platform-scoped access token directly: the token's scope IS the authz
// for the management API, so no RBAC seeding is needed. The admin does need a
// user row -- requireAuth rejects a user token whose subject does not exist.
// Pass a narrower permission list to exercise the missing-permission (403) path.
export async function seedPlatformAdmin(
  userRepo: UserRepository,
  permissions: string[] = PLATFORM_PERMISSIONS,
): Promise<string> {
  const now = new Date()
  await userRepo.create({
    id: 'admin-user',
    email: 'platform-admin@test.local',
    passwordHash: null,
    createdAt: now,
    updatedAt: now,
  })
  return signAccessToken({
    sub: 'admin-user',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'platform',
    org: 'platform',
    scope: permissions.join(' '),
    clientId: 'platform',
    subType: 'user',
  })
}

// Posts the login form the way a browser does: fetch the page, carry its CSRF
// cookie, and submit the token it rendered. Non-browser callers have to do this
// too now — a bare POST to /oauth/authorize is refused (F21).
export async function submitLoginForm(
  app: ReturnType<typeof createApp>,
  fields: Record<string, string>,
): Promise<Response> {
  const q = new URLSearchParams({
    client_id: fields.client_id,
    redirect_uri: fields.redirect_uri,
    scope: fields.scope ?? '',
    state: fields.state ?? '',
    code_challenge: fields.code_challenge,
    code_challenge_method: fields.code_challenge_method,
  })
  const page = await app.request(`/oauth/authorize?${q}`)
  const cookie = page.headers.getSetCookie().map((c) => c.split(';')[0]).join(
    '; ',
  )
  const csrf =
    (await page.text()).match(/name="csrf_token" value="([^"]*)"/)?.[1] ?? ''
  return await app.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ ...fields, csrf_token: csrf }).toString(),
    redirect: 'manual',
  })
}
