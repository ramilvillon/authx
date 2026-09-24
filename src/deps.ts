import type { Config } from './config.ts'
import type { Database } from './db/client.ts'
import type { Logger } from './lib/logger.ts'
import type { AuthenticatedUser } from './types.ts'
import type { UserService } from './modules/users/users.service.ts'
import type { AuthService } from './modules/auth/auth.service.ts'
import type { RateLimitStore } from './lib/rate-limit-store.ts'
import { createUserService } from './modules/users/users.service.ts'
import { createAuthService } from './modules/auth/auth.service.ts'
import { createMemoryRateLimitStore } from './lib/rate-limit-store.ts'
import { createDrizzleUserRepository } from './modules/users/users.repository.drizzle.ts'
import { createDrizzleRefreshTokenRepository } from './modules/auth/token.repository.drizzle.ts'
import { createDrizzleSocialAccountRepository } from './modules/auth/social.repository.drizzle.ts'
import { createDrizzleOrgRepository } from './modules/orgs/orgs.repository.drizzle.ts'
import { createDrizzleRbacRepository } from './modules/rbac/rbac.repository.drizzle.ts'
import { createDrizzleSessionRepository } from './modules/auth/session.repository.drizzle.ts'
import { createDrizzleAuthCodeRepository } from './modules/auth/authcode.repository.drizzle.ts'
import {
  type AdminService,
  createAdminService,
} from './modules/admin/admin.service.ts'
import { type KeySet, loadKeyRing } from './lib/keys.ts'
import { createLogger } from './lib/logger.ts'
import { createLogEmailSender, createSmtpEmailSender } from './lib/email.ts'
import { createDrizzleVerificationTokenRepository } from './modules/verification/verification.repository.drizzle.ts'
import {
  createVerificationService,
  type VerificationService,
} from './modules/verification/verification.service.ts'
import { createDrizzleTotpRepository } from './modules/mfa/totp.repository.drizzle.ts'
import {
  createTotpService,
  type TotpService,
} from './modules/mfa/totp.service.ts'
import { createDrizzlePasskeyRepository } from './modules/passkeys/passkey.repository.drizzle.ts'

export type Deps = {
  config: Config
  keySet: KeySet
  userService: UserService
  authService: AuthService
  adminService: AdminService
  rateStore: RateLimitStore
  verificationService: VerificationService
  totpService: TotpService
}

export async function createDeps(config: Config, db: Database): Promise<Deps> {
  const userRepo = createDrizzleUserRepository(db)
  const tokenRepo = createDrizzleRefreshTokenRepository(db)
  const socialRepo = createDrizzleSocialAccountRepository(db)
  const orgRepo = createDrizzleOrgRepository(db)
  const rbacRepo = createDrizzleRbacRepository(db)
  const sessionRepo = createDrizzleSessionRepository(db)
  const authCodeRepo = createDrizzleAuthCodeRepository(db)
  const verificationRepo = createDrizzleVerificationTokenRepository(db)
  const totpRepo = createDrizzleTotpRepository(db)
  const passkeyRepo = createDrizzlePasskeyRepository(db)
  const totpService = createTotpService({
    totpRepo,
    userRepo,
    issuer: config.issuer,
    encryptionKey: config.totpEncryptionKey,
  })
  // SMTP_HOST is the switch. Unset means local development, where the log
  // sender plus EMAIL_LOG_LINKS=true is enough to click through a flow.
  const logger = createLogger(config)
  const emailSender = config.smtp.host
    ? createSmtpEmailSender(config, logger)
    : createLogEmailSender(logger, config.emailLogLinks)
  const verificationService = createVerificationService({
    verificationRepo,
    userRepo,
    tokenRepo,
    sessionRepo,
    emailSender,
    config,
  })
  const keySet = await loadKeyRing(
    config.jwtPrivateKey,
    config.jwtPublicKey,
    config.jwtPreviousPublicKeys,
  )
  return {
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
      totpRepo,
      passkeyRepo,
      allowPasswordGrant: config.allowPasswordGrant,
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
      logger,
      totp: totpService,
    }),
    adminService: createAdminService({ orgRepo, rbacRepo }),
    verificationService,
    totpService,
  }
}

export type AppEnv = {
  Variables:
    & { requestId: string; logger: Logger }
    & Deps
    & { user: AuthenticatedUser }
}
