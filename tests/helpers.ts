import type { Deps } from '../src/deps.ts'
import { createApp } from '../src/app.ts'
import { loadConfig } from '../src/config.ts'
import { createInMemoryUserRepository } from '../src/modules/users/users.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../src/modules/auth/token.repository.ts'
import { createUserService } from '../src/modules/users/users.service.ts'
import { createAuthService } from '../src/modules/auth/auth.service.ts'
import { ROLE_GRANTS } from '../src/db/rbac-constants.ts'
import { createMemoryRateLimitStore } from '../src/lib/rate-limit-store.ts'
import type { SocialAccountRepository } from '../src/modules/auth/social.repository.ts'

const testEnv = {
  DB_USER: 'app',
  DB_PASS: 'app',
  DB_NAME: 'app',
  JWT_SECRET: 'test-secret',
  LOG_LEVEL: 'silent',
}

export type TestContext = {
  deps: Deps
  userRepo: ReturnType<typeof createInMemoryUserRepository>
  socialRepo: SocialAccountRepository
}

export function makeTestDeps(): TestContext {
  const config = loadConfig(testEnv)
  const userRepo = createInMemoryUserRepository(ROLE_GRANTS)
  const tokenRepo = createInMemoryRefreshTokenRepository()
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
    rateStore: createMemoryRateLimitStore(),
    userService: createUserService({ repo: userRepo }),
    authService: createAuthService({ userRepo, tokenRepo, socialRepo, config }),
  }
  return { deps, userRepo, socialRepo }
}

export function makeTestApp() {
  const { deps, userRepo } = makeTestDeps()
  return { app: createApp(deps), userRepo }
}

export async function authHeader(
  app: ReturnType<typeof createApp>,
  email: string,
  password: string,
) {
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'password', username: email, password }),
  })
  const body = await res.json()
  return {
    Authorization: `Bearer ${body.access_token}`,
    refresh: body.refresh_token as string,
  }
}
