import type { Config } from '../../config.ts'
import type { UserRecord, UserRepository } from '../users/users.repository.ts'
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
import type { Logger } from '../../lib/logger.ts'
import type { TotpService } from '../mfa/totp.service.ts'
import { hashPassword, verifyPassword } from '../../lib/password.ts'
import { signAccessToken, signIdToken } from '../../lib/jwt.ts'
import { claimsForScopes, grantedOidcScopes } from '../../lib/oidc.ts'
import { generateRefreshToken, hashToken } from '../../lib/tokens.ts'
import { AppError } from '../../lib/errors.ts'
import { createLoginAttempts } from '../../lib/login-attempts.ts'
import { verifyChallenge } from '../../lib/pkce.ts'
import { exchangeGoogleAuthCode } from '../../lib/google.ts'

export type AuthService = ReturnType<typeof createAuthService>

export type LoginResult =
  | { kind: 'session'; token: string; userId: string }
  | { kind: 'mfa'; userId: string }

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
  logger: Logger
  totp: Pick<TotpService, 'isEnabled' | 'verify'>
}) {
  const { userRepo, tokenRepo, config, keySet, orgRepo, rbacRepo } = deps
  const { sessionRepo, authCodeRepo, logger } = deps

  // Per-account failure counter. Built here rather than injected: it is
  // process-local state belonging to this service, and every caller already
  // shares one instance of it.
  const loginAttempts = createLoginAttempts(config.loginThrottle)

  // Computed once and reused so failed logins for missing/passwordless users
  // still pay the bcrypt cost, equalizing response timing (no user enumeration).
  let dummyHash: string | null = null
  async function getDummyHash(): Promise<string> {
    if (!dummyHash) {
      dummyHash = await hashPassword('invalid-placeholder-password')
    }
    return dummyHash
  }

  // The one place a password is checked against an account. Both entry points
  // (the password grant and the SSO login form) go through it, so the failure
  // count cannot be dodged by switching endpoint.
  //
  // A locked account still pays the hash cost and answers with the SAME error
  // as a wrong password. A distinct code would be an enumeration oracle:
  // unknown accounts are never tracked, so "locked" would mean "exists".
  //
  // A correct password does NOT clear the failure count: the count is shared
  // with TOTP codes, and a password holder who could reset it by signing in
  // again could guess codes forever. It clears only once a login completes
  // (passwordGrant's non-MFA path, finishLogin, completeMfaLogin).
  async function authenticatePassword(
    user: UserRecord | null,
    password: string,
  ): Promise<UserRecord> {
    const locked = user !== null && loginAttempts.isLocked(user.id)
    // Always run a bcrypt comparison to keep timing constant across the
    // missing-user, passwordless-user, wrong-password and locked branches.
    const hash = locked
      ? await getDummyHash()
      : user?.passwordHash ?? await getDummyHash()
    const passwordOk = await verifyPassword(password, hash)
    if (locked || !user || !user.passwordHash || !passwordOk) {
      // Only count failures for accounts that exist: an unbounded map keyed by
      // whatever a caller sends is a memory-growth vector, and there is nothing
      // to protect on an account that is not there.
      if (user && !locked) loginAttempts.recordFailure(user.id)
      throw AppError.of('invalid_credentials')
    }
    return user
  }

  // Deleting a user removes only the users row; its refresh tokens, sessions,
  // social links and role rows survive. So the users row is the authority:
  // every path that mints or accepts a credential checks the subject exists.
  // One primary-key read, so a deletion costs nothing on the write path.
  async function subjectExists(userId: string): Promise<boolean> {
    return (await userRepo.findById(userId)) !== null
  }

  // REQUIRE_EMAIL_VERIFICATION. Called at every point that issues a token or
  // a session, because refresh tokens slide: a check at login alone would never
  // reach an account that already holds one. A guest has no email, so there is
  // nothing to verify. Callers on a password path must call this only AFTER the
  // password is proven, or an unverified account becomes discoverable by
  // address alone. emailVerified is optional on the record type but NOT NULL
  // DEFAULT false in the table, so a missing value is unverified, as the
  // database has it.
  function requireVerifiedEmail(
    user: Pick<UserRecord, 'email' | 'emailVerified'>,
  ): void {
    if (
      config.requireEmailVerification && user.email !== null &&
      !user.emailVerified
    ) {
      throw AppError.of('email_not_verified')
    }
  }

  // Does `secret` authenticate as `service`? Allow-list on 'public': `type` is
  // a free varchar, so a value the API never writes fails closed and demands
  // the secret. A public client has none to present and always passes.
  async function clientSecretOk(
    service: AppServiceRecord,
    secret: string | undefined,
  ): Promise<boolean> {
    if (service.type === 'public') return true
    return service.clientSecretHash !== null && secret !== undefined &&
      (await hashToken(secret)) === service.clientSecretHash
  }

  // RFC 6749 section 6 / RFC 7009 section 2.1: using or revoking a refresh
  // token that belongs to a confidential client needs that client's
  // credentials. The client must be the token's OWN service: another client
  // authenticating perfectly well as itself is `wrongClient`. A client_id is
  // required from a confidential client and, when a public one sends it, must
  // still match.
  async function authenticateTokenClient(
    service: AppServiceRecord,
    client: { id?: string; secret?: string },
    wrongClient: 'invalid_grant' | 'invalid_client',
  ): Promise<void> {
    if (client.id !== undefined && client.id !== service.clientId) {
      throw AppError.of(wrongClient)
    }
    if (service.type !== 'public' && client.id === undefined) {
      throw AppError.of('invalid_client')
    }
    if (!(await clientSecretOk(service, client.secret))) {
      throw AppError.of('invalid_client')
    }
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
    authTime?: Date,
  ): Promise<TokenPair> {
    const user = await userRepo.findById(userId)
    if (!user) throw AppError.of('invalid_grant')
    requireVerifiedEmail(user)
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
      authTime,
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

  // Where a proven first factor becomes a session -- unless the account has
  // TOTP on, in which case the caller must collect a code first. Every hosted
  // login path (password, Google) ends here, so one check covers them all.
  async function finishLogin(userId: string): Promise<LoginResult> {
    if (await deps.totp.isEnabled(userId)) return { kind: 'mfa', userId }
    loginAttempts.clear(userId)
    return { kind: 'session', ...(await createSession(userId)) }
  }

  return {
    async passwordGrant(
      identifier: string,
      password: string,
      audience: string,
    ): Promise<TokenPair> {
      // Before the lookup: a disabled grant must not count toward the login
      // throttle or cost a bcrypt compare.
      if (!config.allowPasswordGrant) {
        throw AppError.of('unsupported_grant_type')
      }
      // An email or a generated username. Generated usernames never contain
      // '@', so the test is unambiguous in both directions.
      // The lookup is the only thing that branches; everything after it is
      // constant across the missing-user and wrong-password cases.
      const found = identifier.includes('@')
        ? await userRepo.findByEmail(identifier)
        : await userRepo.findByUsername(identifier)
      const user = await authenticatePassword(found, password)
      // After the password, never before: a wrong password stays
      // invalid_grant, so mfa_required tells nothing to someone without it.
      // The grant cannot carry a second factor; TOTP is entered on the hosted
      // login page only.
      if (await deps.totp.isEnabled(user.id)) throw AppError.of('mfa_required')
      loginAttempts.clear(user.id)
      return issueTokensForService(user.id, audience)
    },
    async refreshGrant(
      refreshToken: string,
      client: { id?: string; secret?: string } = {},
    ): Promise<TokenPair> {
      const hash = await hashToken(refreshToken)
      const existing = await tokenRepo.findByHash(hash)
      if (!existing) throw AppError.of('invalid_refresh_token')

      const service = await orgRepo.findServiceById(existing.appServiceId)
      if (!service) throw AppError.of('invalid_refresh_token')
      // BEFORE reuse detection: otherwise anyone holding a stale token but not
      // the client's secret could revoke the real client's whole family.
      await authenticateTokenClient(service, client, 'invalid_grant')

      const isExpired = existing.expiresAt.getTime() <= Date.now()
      // Reuse of an already-revoked token signals theft: revoke the whole family.
      if (existing.revokedAt) {
        await tokenRepo.revokeAllForUser(existing.userId)
        throw AppError.of('refresh_token_reuse')
      }
      if (isExpired) throw AppError.of('invalid_refresh_token')
      // A deleted subject's surviving tokens mint nothing.
      const subject = await userRepo.findById(existing.userId)
      if (!subject) throw AppError.of('invalid_refresh_token')
      // Before rotating: a refused refresh leaves the presented token as it
      // was, usable again once the address is verified.
      requireVerifiedEmail(subject)

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
    async revoke(
      refreshToken: string,
      client: { id?: string; secret?: string } = {},
    ): Promise<void> {
      const existing = await tokenRepo.findByHash(await hashToken(refreshToken))
      // RFC 7009 section 2.2: an unknown token is still a success.
      if (!existing) return
      const service = await orgRepo.findServiceById(existing.appServiceId)
      if (service) {
        await authenticateTokenClient(service, client, 'invalid_client')
      }
      if (!existing.revokedAt) await tokenRepo.revoke(existing.id)
    },
    // Google is a way to sign in to the authorize flow, not a token endpoint:
    // the pending /oauth/authorize request already names the service, so the
    // audience never has to survive the round trip through Google.
    async loginWithGoogle(profile: {
      providerAccountId: string
      email: string
      emailVerified: boolean
    }): Promise<LoginResult> {
      const existing = await deps.socialRepo.findByProviderAccount(
        'google',
        profile.providerAccountId,
      )
      if (existing) {
        // A deleted account keeps its social link until it is purged.
        if (!(await subjectExists(existing.userId))) {
          throw AppError.of('invalid_grant')
        }
        return finishLogin(existing.userId)
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
        return finishLogin(created.id)
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
      return finishLogin(user.id)
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
    ): Promise<LoginResult> {
      const user = await authenticatePassword(
        await userRepo.findByEmail(email),
        password,
      )
      requireVerifiedEmail(user)
      return finishLogin(user.id)
    },
    // The second step of a hosted login. The first factor was proven when
    // the challenge was issued; this proves the second and opens the session.
    // Same per-account lockout as passwords, and the same error whether the
    // account is locked or the code is wrong.
    async completeMfaLogin(
      userId: string,
      code: string,
    ): Promise<{ token: string; userId: string }> {
      if (!(await subjectExists(userId))) throw AppError.of('invalid_grant')
      if (loginAttempts.isLocked(userId)) {
        throw AppError.of('invalid_credentials')
      }
      // Counted BEFORE the await: requests in flight together must each see
      // the others' attempts, or a burst walks straight past the limit. A
      // correct code clears the count below.
      loginAttempts.recordFailure(userId)
      if (!(await deps.totp.verify(userId, code))) {
        throw AppError.of('invalid_credentials')
      }
      loginAttempts.clear(userId)
      return createSession(userId)
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
      if (!(await clientSecretOk(service, input.clientSecret))) {
        throw AppError.of('invalid_client')
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
        record.authTime,
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
    // Binding while authenticated: the bearer token proves which local row to
    // attach to, rather than inferring it from an email string the way
    // loginWithGoogle's fallback path does.
    async linkGoogleToUser(userId: string, code: string): Promise<void> {
      const google = config.google
      // Half-configured (a client id with no secret) must fail closed here,
      // not three lines down as an opaque invalid_grant from Google.
      if (!google.clientId || !google.clientSecret) {
        throw AppError.of('google_login_disabled')
      }
      // Looked up BEFORE redeeming the code: a client-credentials (service)
      // token has no user row, and requireAuth alone does not reject it. Doing
      // this after the exchange would burn a one-time Google code on a
      // request that was always going to fail user_not_found.
      const user = await userRepo.findById(userId)
      if (!user) throw AppError.of('user_not_found')

      const identity = await exchangeGoogleAuthCode(code, {
        clientId: google.clientId,
        clientSecret: google.clientSecret,
        // Empty by default, which means no redirect_uri on the wire -- the
        // native SDK case. See GOOGLE_BIND_REDIRECT_URI in config.ts for when
        // a client needs one of the other two answers.
        redirectUri: google.bindRedirectUri,
      }, logger)
      // Never link on an unproven address -- same rule as loginWithGoogle.
      if (!identity.emailVerified) {
        throw AppError.of('google_email_unverified')
      }

      const existing = await deps.socialRepo.findByProviderAccount(
        'google',
        identity.sub,
      )
      if (existing && existing.userId !== userId) {
        throw AppError.of('social_account_already_linked')
      }

      // Only an account with no address takes Google's. A user who already has
      // one keeps it: without this condition, binding would be a second route
      // to an unauthorised email change (the F6 shape).
      const takesEmail = !user.email

      // A retry of a FULLY complete bind (already linked, already has an
      // email) is success with no side effects. But a retry that is linked
      // and still has no email is the shape decision 8 rejects: an earlier
      // attempt's email patch AND its compensating deleteAllForUser both
      // failed against the same outage (they are not independent), leaving
      // the account linked-but-emailless forever unless this reconciles it.
      // Falling through re-runs the collision check and the adoption below.
      if (existing && !takesEmail) return

      if (takesEmail && await userRepo.findAnyByEmail(identity.email)) {
        // findAnyByEmail, not findByEmail: a soft-deleted row still occupies
        // the address until db:prune erases it. Fires on the reconcile path
        // too: if the address was taken by someone else in the meantime, the
        // answer is still email_taken, never a silent second success.
        throw AppError.of('email_taken')
      }

      if (!existing) {
        // link() first: UNIQUE(provider, provider_account_id) is what
        // atomically claims the Google account against a concurrent bind.
        await deps.socialRepo.link({
          id: crypto.randomUUID(),
          userId,
          provider: 'google',
          providerAccountId: identity.sub,
        })
      }
      if (takesEmail) {
        // Through the internal repo patch, never a client-facing schema:
        // emailVerified is mass-assignment protected (Phase 4).
        //
        // The link must never survive a failed patch IF this call is the one
        // that created it (!existing) -- "failed" has two shapes here.
        // users.repository.drizzle.ts's update() throws straight out of a
        // duplicate-key insert rather than returning null -- it never reaches
        // its own `return findById(id)` -- so a lost race on the address
        // surfaces as an exception, not a falsy return. Catch it, compensate,
        // and rethrow the original error rather than relabelling it
        // email_taken: we have no driver-independent way here to tell a
        // duplicate-key race (the likely cause, given the findAnyByEmail
        // pre-check just above) apart from an unrelated failure such as a DB
        // outage, and reporting an outage as email_taken would send the
        // client down the wrong path.
        //
        // deleteAllForUser is safe as this compensation only because a guest
        // reaching this branch has no other social link to lose -- Google is
        // the only provider this codebase supports. A second provider or an
        // unlink endpoint would make this collateral deletion; whoever adds
        // one should delete by (provider, providerAccountId) instead.
        //
        // On the reconcile path (existing is already ours from a previous
        // attempt) a second failure must NOT delete that link -- it is real
        // and this call did not create it -- so compensation only runs when
        // this call is the one that created the link.
        let patched
        try {
          patched = await userRepo.update(userId, {
            email: identity.email,
            emailVerified: true,
          })
        } catch (err) {
          if (!existing) await deps.socialRepo.deleteAllForUser(userId)
          throw err
        }
        if (!patched) {
          // The clean (non-throwing) way to lose the row: it vanished --
          // e.g. soft-deleted -- between findById above and this update, so
          // update() matched nothing rather than hitting a constraint. Same
          // compensation.
          if (!existing) await deps.socialRepo.deleteAllForUser(userId)
          throw AppError.of('email_taken')
        }
      }
    },
  }
}
