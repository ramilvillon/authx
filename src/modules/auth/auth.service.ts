import type { Config } from '../../config.ts'
import type { UserRepository } from '../users/users.repository.ts'
import type {
  NewRefreshToken,
  RefreshTokenRepository,
} from './token.repository.ts'
import type { SocialAccountRepository } from './social.repository.ts'
import type { TokenPair } from './auth.schema.ts'
import { hashPassword, verifyPassword } from '../../lib/password.ts'
import { signAccessToken } from '../../lib/jwt.ts'
import { generateRefreshToken, hashToken } from '../../lib/tokens.ts'
import { AppError } from '../../lib/errors.ts'

export type AuthService = ReturnType<typeof createAuthService>

export function createAuthService(deps: {
  userRepo: UserRepository
  tokenRepo: RefreshTokenRepository
  socialRepo: SocialAccountRepository
  config: Config
}) {
  const { userRepo, tokenRepo, config } = deps

  // Computed once and reused so failed logins for missing/passwordless users
  // still pay the bcrypt cost, equalizing response timing (no user enumeration).
  let dummyHash: string | null = null
  async function getDummyHash(): Promise<string> {
    if (!dummyHash) {
      dummyHash = await hashPassword('invalid-placeholder-password')
    }
    return dummyHash
  }

  async function issueTokens(userId: string): Promise<TokenPair> {
    const access_token = await signAccessToken({
      sub: userId,
      secret: config.jwtSecret,
      ttlSeconds: config.accessTokenTtl,
    })
    const refresh = generateRefreshToken()
    const record: NewRefreshToken = {
      id: crypto.randomUUID(),
      userId,
      tokenHash: await hashToken(refresh),
      expiresAt: new Date(Date.now() + config.refreshTokenTtl * 1000),
    }
    await tokenRepo.create(record)
    return {
      access_token,
      refresh_token: refresh,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtl,
    }
  }

  return {
    issueTokens,
    async passwordGrant(email: string, password: string): Promise<TokenPair> {
      const user = await userRepo.findByEmail(email)
      // Always run a bcrypt comparison to keep timing constant across the
      // missing-user, passwordless-user, and wrong-password branches.
      const hash = user?.passwordHash ?? await getDummyHash()
      const passwordOk = await verifyPassword(password, hash)
      if (!user || !user.passwordHash || !passwordOk) {
        throw AppError.unauthorized('invalid credentials')
      }
      return issueTokens(user.id)
    },
    async refreshGrant(refreshToken: string): Promise<TokenPair> {
      const hash = await hashToken(refreshToken)
      const existing = await tokenRepo.findByHash(hash)
      if (!existing) throw AppError.unauthorized('invalid refresh token')

      const isExpired = existing.expiresAt.getTime() <= Date.now()
      // Reuse of an already-revoked token signals theft: revoke the whole family.
      if (existing.revokedAt) {
        await tokenRepo.revokeAllForUser(existing.userId)
        throw AppError.unauthorized('refresh token reuse detected')
      }
      if (isExpired) throw AppError.unauthorized('invalid refresh token')

      const refresh = generateRefreshToken()
      const next: NewRefreshToken = {
        id: crypto.randomUUID(),
        userId: existing.userId,
        tokenHash: await hashToken(refresh),
        expiresAt: new Date(Date.now() + config.refreshTokenTtl * 1000),
      }
      // Sign the access token before rotating so the only step after a
      // successful (irreversible) rotation is returning the response.
      const access_token = await signAccessToken({
        sub: existing.userId,
        secret: config.jwtSecret,
        ttlSeconds: config.accessTokenTtl,
      })
      // Atomic rotation; a false result means a concurrent rotation already
      // consumed this token (replay), so revoke the family and reject.
      if (!(await tokenRepo.rotate(existing.id, next))) {
        await tokenRepo.revokeAllForUser(existing.userId)
        throw AppError.unauthorized('refresh token reuse detected')
      }
      return {
        access_token,
        refresh_token: refresh,
        token_type: 'Bearer',
        expires_in: config.accessTokenTtl,
      }
    },
    async revoke(refreshToken: string): Promise<void> {
      const existing = await tokenRepo.findByHash(await hashToken(refreshToken))
      if (existing && !existing.revokedAt) await tokenRepo.revoke(existing.id)
    },
    async loginWithGoogle(
      profile: {
        providerAccountId: string
        email: string
        emailVerified: boolean
      },
    ): Promise<TokenPair> {
      const existing = await deps.socialRepo.findByProviderAccount(
        'google',
        profile.providerAccountId,
      )
      if (existing) return issueTokens(existing.userId)

      // Never create-or-link an account from an unverified provider email:
      // that would let an attacker take over an account by claiming its email.
      if (!profile.emailVerified) {
        throw AppError.forbidden('google account email is not verified')
      }

      let user = await userRepo.findByEmail(profile.email)
      if (!user) {
        const now = new Date()
        user = await userRepo.create({
          id: crypto.randomUUID(),
          email: profile.email,
          passwordHash: null,
          createdAt: now,
          updatedAt: now,
        })
        await userRepo.assignRole(user.id, 'user')
      }
      await deps.socialRepo.link({
        id: crypto.randomUUID(),
        userId: user.id,
        provider: 'google',
        providerAccountId: profile.providerAccountId,
      })
      return issueTokens(user.id)
    },
    async resolveUser(userId: string) {
      const user = await userRepo.findWithAccessById(userId)
      if (!user) throw AppError.unauthorized('user not found')
      return {
        id: user.id,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
      }
    },
  }
}
