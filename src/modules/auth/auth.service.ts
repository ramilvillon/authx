import type { Config } from '../../config.ts'
import type { UserRepository } from '../users/users.repository.ts'
import type {
  NewRefreshToken,
  RefreshTokenRepository,
} from './token.repository.ts'
import type { SocialAccountRepository } from './social.repository.ts'
import type { TokenPair } from './auth.schema.ts'
import type { KeySet } from '../../lib/keys.ts'
import type {
  AppServiceRecord,
  OrgRepository,
} from '../orgs/orgs.repository.ts'
import type { RbacRepository } from '../rbac/rbac.repository.ts'
import type { SessionRepository } from './session.repository.ts'
import type { AuthCodeRepository } from './authcode.repository.ts'
import { hashPassword, verifyPassword } from '../../lib/password.ts'
import { signAccessToken } from '../../lib/jwt.ts'
import { generateRefreshToken, hashToken } from '../../lib/tokens.ts'
import { AppError } from '../../lib/errors.ts'
import { verifyChallenge } from '../../lib/pkce.ts'

export type AuthService = ReturnType<typeof createAuthService>

export function createAuthService(deps: {
  userRepo: UserRepository
  tokenRepo: RefreshTokenRepository
  socialRepo: SocialAccountRepository
  orgRepo: OrgRepository
  rbacRepo: RbacRepository
  config: Config
  keySet: KeySet
  sessionRepo: SessionRepository
  authCodeRepo: AuthCodeRepository
}) {
  const { userRepo, tokenRepo, config, keySet, orgRepo, rbacRepo } = deps
  const { sessionRepo, authCodeRepo } = deps

  // Computed once and reused so failed logins for missing/passwordless users
  // still pay the bcrypt cost, equalizing response timing (no user enumeration).
  let dummyHash: string | null = null
  async function getDummyHash(): Promise<string> {
    if (!dummyHash) {
      dummyHash = await hashPassword('invalid-placeholder-password')
    }
    return dummyHash
  }

  async function issueTokensForService(
    userId: string,
    audience: string,
  ): Promise<TokenPair> {
    const service = await orgRepo.findServiceByAudience(audience)
    if (!service) throw AppError.badRequest('unknown audience')
    if (!(await orgRepo.isMember(userId, service.orgId))) {
      throw AppError.forbidden('not a member of this organization')
    }
    const scopes = await rbacRepo.permissionsForUserInService(
      userId,
      service.id,
    )
    const access_token = await signAccessToken({
      sub: userId,
      issuer: config.issuer,
      privateKeyPem: keySet.privateKeyPem,
      kid: keySet.kid,
      ttlSeconds: config.accessTokenTtl,
      aud: service.audience,
      org: service.orgId,
      scope: scopes.join(' '),
      clientId: service.clientId,
    })
    const refresh = generateRefreshToken()
    await tokenRepo.create({
      id: crypto.randomUUID(),
      userId,
      appServiceId: service.id,
      tokenHash: await hashToken(refresh),
      expiresAt: new Date(Date.now() + config.refreshTokenTtl * 1000),
    })
    return {
      access_token,
      refresh_token: refresh,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtl,
    }
  }

  return {
    async passwordGrant(
      email: string,
      password: string,
      audience: string,
    ): Promise<TokenPair> {
      const user = await userRepo.findByEmail(email)
      // Always run a bcrypt comparison to keep timing constant across the
      // missing-user, passwordless-user, and wrong-password branches.
      const hash = user?.passwordHash ?? await getDummyHash()
      const passwordOk = await verifyPassword(password, hash)
      if (!user || !user.passwordHash || !passwordOk) {
        throw AppError.unauthorized('invalid credentials')
      }
      return issueTokensForService(user.id, audience)
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

      const service = await orgRepo.findServiceById(existing.appServiceId)
      if (!service) throw AppError.unauthorized('invalid refresh token')
      const scopes = await rbacRepo.permissionsForUserInService(
        existing.userId,
        service.id,
      )
      const refresh = generateRefreshToken()
      const next: NewRefreshToken = {
        id: crypto.randomUUID(),
        userId: existing.userId,
        appServiceId: service.id,
        tokenHash: await hashToken(refresh),
        expiresAt: new Date(Date.now() + config.refreshTokenTtl * 1000),
      }
      // Sign the access token before rotating so the only step after a
      // successful (irreversible) rotation is returning the response.
      const access_token = await signAccessToken({
        sub: existing.userId,
        issuer: config.issuer,
        privateKeyPem: keySet.privateKeyPem,
        kid: keySet.kid,
        ttlSeconds: config.accessTokenTtl,
        aud: service.audience,
        org: service.orgId,
        scope: scopes.join(' '),
        clientId: service.clientId,
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
      audience: string,
    ): Promise<TokenPair> {
      const existing = await deps.socialRepo.findByProviderAccount(
        'google',
        profile.providerAccountId,
      )
      if (existing) return issueTokensForService(existing.userId, audience)

      // Never create-or-link an account from an unverified provider email:
      // that would let an attacker take over an account by claiming its email.
      if (!profile.emailVerified) {
        throw AppError.forbidden('google account email is not verified')
      }

      const user = await userRepo.findByEmail(profile.email)
      if (!user) {
        const now = new Date()
        const created = await userRepo.create({
          id: crypto.randomUUID(),
          email: profile.email,
          passwordHash: null,
          createdAt: now,
          updatedAt: now,
        })
        // No assignRole — roles are per-service, granted via the management API.
        await deps.socialRepo.link({
          id: crypto.randomUUID(),
          userId: created.id,
          provider: 'google',
          providerAccountId: profile.providerAccountId,
        })
        return issueTokensForService(created.id, audience)
      }

      if (user.passwordHash !== null) {
        // Pre-hijacking guard: a local account with a password must prove
        // ownership via password login before linking a social provider.
        throw AppError.forbidden(
          'an account with this email already exists; sign in with your password to link Google',
        )
      }

      // Passwordless user (e.g., invite-created): safe to link.
      await deps.socialRepo.link({
        id: crypto.randomUUID(),
        userId: user.id,
        provider: 'google',
        providerAccountId: profile.providerAccountId,
      })
      return issueTokensForService(user.id, audience)
    },
    async validateAuthorizeRequest(p: {
      clientId: string
      redirectUri: string
      codeChallenge: string
      codeChallengeMethod: string
    }): Promise<AppServiceRecord> {
      const service = await orgRepo.findServiceByClientId(p.clientId)
      if (!service) throw AppError.badRequest('unknown client_id')
      if (!service.redirectUris.includes(p.redirectUri)) {
        throw AppError.badRequest('redirect_uri not allowed')
      }
      if (p.codeChallengeMethod !== 'S256' || !p.codeChallenge) {
        throw AppError.badRequest('code_challenge with S256 is required')
      }
      return service
    },
    async userIdForSession(sessionToken: string): Promise<string | null> {
      const session = await sessionRepo.findActiveByTokenHash(
        await hashToken(sessionToken),
      )
      return session?.userId ?? null
    },
    async issueAuthorizationCode(
      userId: string,
      service: AppServiceRecord,
      p: {
        redirectUri: string
        scope: string
        codeChallenge: string
        codeChallengeMethod: string
      },
    ): Promise<string> {
      const code = generateRefreshToken()
      await authCodeRepo.create({
        id: crypto.randomUUID(),
        codeHash: await hashToken(code),
        userId,
        appServiceId: service.id,
        redirectUri: p.redirectUri,
        codeChallenge: p.codeChallenge,
        codeChallengeMethod: p.codeChallengeMethod,
        scope: p.scope,
        expiresAt: new Date(Date.now() + config.authCodeTtl * 1000),
      })
      return code
    },
    async loginCreateSession(
      email: string,
      password: string,
    ): Promise<{ token: string; userId: string }> {
      const user = await userRepo.findByEmail(email)
      // Constant-time across missing/passwordless/wrong-password (see passwordGrant).
      const hash = user?.passwordHash ?? await getDummyHash()
      const passwordOk = await verifyPassword(password, hash)
      if (!user || !user.passwordHash || !passwordOk) {
        throw AppError.unauthorized('invalid credentials')
      }
      const token = generateRefreshToken()
      await sessionRepo.create({
        id: crypto.randomUUID(),
        userId: user.id,
        tokenHash: await hashToken(token),
        expiresAt: new Date(Date.now() + config.ssoSessionTtl * 1000),
      })
      return { token, userId: user.id }
    },
    async exchangeAuthorizationCode(input: {
      code: string
      redirectUri: string
      codeVerifier: string
      clientId: string
      clientSecret?: string
    }): Promise<TokenPair> {
      const record = await authCodeRepo.findByCodeHash(
        await hashToken(input.code),
      )
      if (!record) throw AppError.badRequest('invalid_grant')

      const service = await orgRepo.findServiceById(record.appServiceId)
      if (!service || service.clientId !== input.clientId) {
        throw AppError.badRequest('invalid_grant')
      }
      // Confidential clients must authenticate (secret stored as sha256, like Phase 1).
      if (service.type === 'confidential') {
        const ok = service.clientSecretHash !== null &&
          input.clientSecret !== undefined &&
          (await hashToken(input.clientSecret)) === service.clientSecretHash
        if (!ok) throw AppError.unauthorized('invalid_client')
      }
      // Replay of a consumed code: the code (and any token minted from it) may be
      // compromised — revoke the user's refresh-token family.
      if (record.consumedAt) {
        await tokenRepo.revokeAllForUser(record.userId)
        throw AppError.badRequest('invalid_grant')
      }
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.badRequest('invalid_grant')
      }
      if (record.redirectUri !== input.redirectUri) {
        throw AppError.badRequest('invalid_grant')
      }
      if (!(await verifyChallenge(input.codeVerifier, record.codeChallenge))) {
        throw AppError.badRequest('invalid_grant')
      }
      // Single-use; a lost race here is also a replay.
      if (!(await authCodeRepo.consume(record.id))) {
        await tokenRepo.revokeAllForUser(record.userId)
        throw AppError.badRequest('invalid_grant')
      }
      return issueTokensForService(record.userId, service.audience)
    },
    async logout(sessionToken: string): Promise<void> {
      const session = await sessionRepo.findActiveByTokenHash(
        await hashToken(sessionToken),
      )
      if (session) await sessionRepo.revoke(session.id)
    },
  }
}
