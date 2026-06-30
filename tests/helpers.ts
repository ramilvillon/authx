import type { Deps } from '../src/deps.ts'
import { createApp } from '../src/app.ts'
import { loadConfig } from '../src/config.ts'
import { createInMemoryUserRepository } from '../src/modules/users/users.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../src/modules/auth/token.repository.ts'
import { createInMemoryOrgRepository } from '../src/modules/orgs/orgs.repository.ts'
import { createInMemoryRbacRepository } from '../src/modules/rbac/rbac.repository.ts'
import { createUserService } from '../src/modules/users/users.service.ts'
import { createAuthService } from '../src/modules/auth/auth.service.ts'
import { ROLE_GRANTS } from '../src/db/rbac-constants.ts'
import { createMemoryRateLimitStore } from '../src/lib/rate-limit-store.ts'
import type { SocialAccountRepository } from '../src/modules/auth/social.repository.ts'
import type { OrgRepository } from '../src/modules/orgs/orgs.repository.ts'
import { generateRsaKeyPairPem, loadKeySet } from '../src/lib/keys.ts'

const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
export const keySet = await loadKeySet(privateKeyPem, publicKeyPem)

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
  socialRepo: SocialAccountRepository
  orgRepo: ReturnType<typeof createInMemoryOrgRepository>
  rbacRepo: ReturnType<typeof createInMemoryRbacRepository>
}

export function makeTestDeps(): TestContext {
  const config = loadConfig(testEnv)
  const userRepo = createInMemoryUserRepository(ROLE_GRANTS)
  const tokenRepo = createInMemoryRefreshTokenRepository()
  const orgRepo = createInMemoryOrgRepository()
  const rbacRepo = createInMemoryRbacRepository()
  const social = new Map<string, string>()
  const socialRepo: SocialAccountRepository = {
    findByProviderAccount: (p, id) =>
      Promise.resolve(
        social.has(`${p}:${id}`) ? { userId: social.get(`${p}:${id}`)! } : null,
      ),
    link: (a) => {
      social.set(`${a.provider}:${a.providerAccountId}`, a.userId)
      return Promise.resolve()
    },
  }
  const deps: Deps = {
    config,
    keySet,
    rateStore: createMemoryRateLimitStore(),
    userService: createUserService({ repo: userRepo }),
    authService: createAuthService({
      userRepo,
      tokenRepo,
      socialRepo,
      orgRepo,
      rbacRepo,
      config,
      keySet,
    }),
  }
  return { deps, userRepo, socialRepo, orgRepo, rbacRepo }
}

export function makeTestApp() {
  const { deps, userRepo, orgRepo, rbacRepo } = makeTestDeps()
  return { app: createApp(deps), userRepo, orgRepo, rbacRepo }
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
