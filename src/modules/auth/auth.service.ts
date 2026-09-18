import type { Config } from '../../config.ts'
import type { UserRepository } from '../users/users.repository.ts'
import type {
  NewRefreshToken,
  RefreshTokenRepository,
} from './token.repository.ts'
import type { SocialAccountRepository } from './social.repository.ts'
import type { ClientCredentialsResponse, TokenPair } from './auth.schema.ts'
import type { KeySet } from '../../lib/keys.ts'
import type {
  AppServiceRecord,
  OrgRepository,
} from '../orgs/orgs.repository.ts'
import type { RbacRepository } from '../rbac/rbac.repository.ts'
import type { SessionRepository } from './session.repository.ts'
import type { AuthCodeRepository } from './authcode.repository.ts'
import { hashPassword, verifyPassword } from '../../lib/password.ts'
import { signAccessToken, signIdToken } from '../../lib/jwt.ts'
import { claimsForScopes, grantedOidcScopes } from '../../lib/oidc.ts'
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

  // Deleting a user removes only the users row; its refresh tokens, sessions,
  // social links and role rows survive. So the users row is the authority:
  // every path that mints or accepts a credential checks the subject exists.
  // One primary-key read, so a deletion costs nothing on the write path.
  async function subjectExists(userId: string): Promise<boolean> {
    return (await userRepo.findById(userId)) !== null
  }

  async function activeSession(sessionToken: string) {
    const session = await sessionRepo.findActiveByTokenHash(
      await hashToken(sessionToken),
    )
    if (!session || !(await subjectExists(session.userId))) return null
    return session
  }

  async function issueTokensForService(
    userId: string,
    audience: string,
    oidcScope?: string,
  ): Promise<TokenPair> {
    if (!(await subjectExists(userId))) throw AppError.of('invalid_grant')
    const service = await orgRepo.findServiceByAudience(audience)
    if (!service) throw AppError.of('unknown_audience')
    if (!(await orgRepo.isMember(userId, service.orgId))) {
      throw AppError.of('not_org_member')
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
      oidcScope,
      subType: 'user',
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

  // An SSO session for a user who has already proven who they are. Both login
  // paths (password, Google) end here; the authorization code comes after.
  async function createSession(
    userId: string,
  ): Promise<{ token: string; userId: string }> {
    const token = generateRefreshToken()
    await sessionRepo.create({
      id: crypto.randomUUID(),
      userId,
      tokenHash: await hashToken(token),
      expiresAt: new Date(Date.now() + config.ssoSessionTtl * 1000),
    })
    return { token, userId }
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
        throw AppError.of('invalid_credentials')
      }
      return issueTokensForService(user.id, audience)
    },
    async refreshGrant(refreshToken: string): Promise<TokenPair> {
      const hash = await hashToken(refreshToken)
      const existing = await tokenRepo.findByHash(hash)
      if (!existing) throw AppError.of('invalid_refresh_token')

      const isExpired = existing.expiresAt.getTime() <= Date.now()
      // Reuse of an already-revoked token signals theft: revoke the whole family.
      if (existing.revokedAt) {
        await tokenRepo.revokeAllForUser(existing.userId)
        throw AppError.of('refresh_token_reuse')
      }
      if (isExpired) throw AppError.of('invalid_refresh_token')
      // A deleted subject's surviving tokens mint nothing.
      if (!(await subjectExists(existing.userId))) {
        throw AppError.of('invalid_refresh_token')
      }

      const service = await orgRepo.findServiceById(existing.appServiceId)
      if (!service) throw AppError.of('invalid_refresh_token')
      // Re-check membership on every rotation, exactly as issueTokensForService
      // does at first issue: removing a member is the revocation control, and
      // without this a removed user could keep rotating forever.
      if (!(await orgRepo.isMember(existing.userId, service.orgId))) {
        throw AppError.of('not_org_member')
      }
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
        subType: 'user',
      })
      // Atomic rotation; a false result means a concurrent rotation already
      // consumed this token (replay), so revoke the family and reject.
      if (!(await tokenRepo.rotate(existing.id, next))) {
        await tokenRepo.revokeAllForUser(existing.userId)
        throw AppError.of('refresh_token_reuse')
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
    // Google is a way to sign in to the authorize flow, not a token endpoint:
    // the pending /oauth/authorize request already names the service, so the
    // audience never has to survive the round trip through Google.
    async loginWithGoogle(profile: {
      providerAccountId: string
      email: string
      emailVerified: boolean
    }): Promise<{ token: string; userId: string }> {
      const existing = await deps.socialRepo.findByProviderAccount(
        'google',
        profile.providerAccountId,
      )
      if (existing) {
        // A deleted account keeps its social link until it is purged.
        if (!(await subjectExists(existing.userId))) {
          throw AppError.of('invalid_grant')
        }
        return createSession(existing.userId)
      }

      // Never create-or-link an account from an unverified provider email:
      // that would let an attacker take over an account by claiming its email.
      if (!profile.emailVerified) {
        throw AppError.of('google_email_unverified')
      }

      const user = await userRepo.findByEmail(profile.email)
      if (!user) {
        // findByEmail hides soft-deleted rows, but users.email is UNIQUE, so
        // one of them still occupies the address and creating here would be a
        // duplicate-key error at the database. Same reason register() checks
        // findAnyByEmail. The address stays reserved until the grace period
        // ends and db:prune erases the account.
        if (await userRepo.findAnyByEmail(profile.email)) {
          throw AppError.of('email_taken')
        }
        const now = new Date()
        const created = await userRepo.create({
          id: crypto.randomUUID(),
          email: profile.email,
          passwordHash: null,
          // Only reachable with profile.emailVerified (checked above), so the
          // address is already proven -- verifying it again by email would ask
          // for what Google just established, and leaving it false would put
          // email_verified: false in this account's id_token.
          emailVerified: true,
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
        return createSession(created.id)
      }

      if (user.passwordHash !== null || !user.emailVerified) {
        // Pre-hijacking guard: a local account must prove ownership before a
        // social provider is linked to it — via password login if it has a
        // password, or by verifying its email if it does not. Same error for
        // both so the response does not reveal which.
        throw AppError.of('account_exists_link_password')
      }

      // Passwordless *and* verified: the email challenge already proved
      // ownership, so linking is safe.
      await deps.socialRepo.link({
        id: crypto.randomUUID(),
        userId: user.id,
        provider: 'google',
        providerAccountId: profile.providerAccountId,
      })
      return createSession(user.id)
    },
    async validateAuthorizeRequest(p: {
      clientId: string
      redirectUri: string
      codeChallenge: string
      codeChallengeMethod: string
    }): Promise<AppServiceRecord> {
      const service = await orgRepo.findServiceByClientId(p.clientId)
      if (!service) throw AppError.of('unknown_client_id')
      if (!service.redirectUris.includes(p.redirectUri)) {
        throw AppError.of('redirect_uri_not_allowed')
      }
      if (p.codeChallengeMethod !== 'S256' || !p.codeChallenge) {
        throw AppError.of('code_challenge_required')
      }
      return service
    },
    async userIdForSession(sessionToken: string): Promise<string | null> {
      return (await activeSession(sessionToken))?.userId ?? null
    },
    async resolveSession(
      sessionToken: string,
    ): Promise<{ userId: string; authTime: Date } | null> {
      const session = await activeSession(sessionToken)
      return session
        ? { userId: session.userId, authTime: session.createdAt }
        : null
    },
    async issueAuthorizationCode(
      userId: string,
      service: AppServiceRecord,
      p: {
        redirectUri: string
        scope: string
        codeChallenge: string
        codeChallengeMethod: string
        nonce?: string
        authTime: Date
      },
    ): Promise<string> {
      // ponytail: guard here (the only writer) so the DB never holds a non-S256 record.
      if (p.codeChallengeMethod !== 'S256') {
        throw AppError.of('unsupported_code_challenge_method')
      }
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
        nonce: p.nonce ?? null,
        authTime: p.authTime,
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
        throw AppError.of('invalid_credentials')
      }
      return createSession(user.id)
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
      if (!record) throw AppError.of('invalid_grant')

      const service = await orgRepo.findServiceById(record.appServiceId)
      if (!service || service.clientId !== input.clientId) {
        throw AppError.of('invalid_grant')
      }
      // Replay of a consumed code: the code (and any token minted from it) may be
      // compromised — revoke the user's refresh-token family.
      // Must fire BEFORE client-auth so a replay with a wrong secret still revokes.
      if (record.consumedAt) {
        await tokenRepo.revokeAllForUser(record.userId)
        throw AppError.of('invalid_grant')
      }
      if (record.expiresAt.getTime() <= Date.now()) {
        throw AppError.of('invalid_grant')
      }
      if (record.redirectUri !== input.redirectUri) {
        throw AppError.of('invalid_grant')
      }
      // Every client except a public one must authenticate (secret stored as
      // sha256). Allow-list on 'public': `type` is a free varchar, so a value the
      // API never writes fails closed instead of skipping the secret.
      if (service.type !== 'public') {
        const ok = service.clientSecretHash !== null &&
          input.clientSecret !== undefined &&
          (await hashToken(input.clientSecret)) === service.clientSecretHash
        if (!ok) throw AppError.of('invalid_client')
      }
      if (!(await verifyChallenge(input.codeVerifier, record.codeChallenge))) {
        throw AppError.of('invalid_grant')
      }
      // Single-use; a lost race here is also a replay.
      if (!(await authCodeRepo.consume(record.id))) {
        await tokenRepo.revokeAllForUser(record.userId)
        throw AppError.of('invalid_grant')
      }
      const oidc = grantedOidcScopes(record.scope)
      const pair = await issueTokensForService(
        record.userId,
        service.audience,
        oidc.length ? oidc.join(' ') : undefined,
      )
      if (!oidc.includes('openid')) return pair
      const user = await userRepo.findById(record.userId)
      if (!user) return pair
      const id_token = await signIdToken({
        issuer: config.issuer,
        privateKeyPem: keySet.privateKeyPem,
        kid: keySet.kid,
        ttlSeconds: config.accessTokenTtl,
        sub: user.id,
        aud: input.clientId,
        authTime: record.authTime,
        nonce: record.nonce,
        claims: claimsForScopes(user, oidc),
      })
      return { ...pair, id_token }
    },
    async logout(sessionToken: string): Promise<void> {
      const session = await sessionRepo.findActiveByTokenHash(
        await hashToken(sessionToken),
      )
      if (session) await sessionRepo.revoke(session.id)
    },
    async clientCredentialsGrant(
      clientId: string,
      clientSecret: string,
      audience: string,
    ): Promise<ClientCredentialsResponse> {
      const requesting = await orgRepo.findServiceByClientId(clientId)
      if (
        !requesting || requesting.type !== 'confidential' ||
        requesting.clientSecretHash === null ||
        (await hashToken(clientSecret)) !== requesting.clientSecretHash
      ) {
        throw AppError.of('invalid_client')
      }
      const target = await orgRepo.findServiceByAudience(audience)
      if (!target) throw AppError.of('invalid_request')

      const scopes = await rbacRepo.permissionsForClientInService(
        requesting.id,
        target.id,
      )
      const access_token = await signAccessToken({
        sub: requesting.id,
        issuer: config.issuer,
        privateKeyPem: keySet.privateKeyPem,
        kid: keySet.kid,
        ttlSeconds: config.accessTokenTtl,
        aud: target.audience,
        org: target.orgId,
        scope: scopes.join(' '),
        clientId: requesting.clientId,
        // `sub` is the calling app service, not a user.
        subType: 'service',
      })
      return {
        access_token,
        token_type: 'Bearer',
        expires_in: config.accessTokenTtl,
      }
    },
  }
}
