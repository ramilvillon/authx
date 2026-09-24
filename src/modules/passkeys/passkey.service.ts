import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import type {
  ChallengePurpose,
  PasskeyRepository,
} from './passkey.repository.ts'
import type { UserRepository } from '../users/users.repository.ts'
import { AppError } from '../../lib/errors.ts'
import { hashToken } from '../../lib/tokens.ts'

export type PasskeyService = ReturnType<typeof createPasskeyService>
export type PasskeySummary = {
  id: string
  created_at: string
  last_used_at: string | null
  backed_up: boolean
  aaguid: string
}

export const MAX_PASSKEYS = 20
const CHALLENGE_TTL_MS = 5 * 60 * 1000
// Same step-up window as TOTP enrolment.
const FRESH_LOGIN_MS = 5 * 60 * 1000
const ALGORITHMS = [-7, -257] // ES256, RS256

type AuthResponse = Parameters<
  typeof verifyAuthenticationResponse
>[0]['response']
type RegResponse = Parameters<typeof verifyRegistrationResponse>[0]['response']
type Transports = NonNullable<
  Parameters<typeof verifyAuthenticationResponse>[0]['credential']['transports']
>

export function createPasskeyService(deps: {
  passkeyRepo: PasskeyRepository
  userRepo: UserRepository
  // '' = passkeys off.
  rpId: string
  origin: string
}) {
  const { passkeyRepo, userRepo, rpId, origin } = deps
  const enabled = rpId !== ''

  function requireEnabled() {
    if (!enabled) throw AppError.of('passkey_not_configured')
  }

  async function storeChallenge(
    challenge: string,
    purpose: ChallengePurpose,
    userId: string | null,
  ) {
    await passkeyRepo.createChallenge({
      challengeHash: await hashToken(challenge),
      purpose,
      userId,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    })
  }

  // Handed to the library as expectedChallenge: it is called with the
  // challenge the browser signed, and consuming it IS the check -- one
  // conditional update, so a replay or a parallel duplicate loses.
  const consume =
    (purpose: ChallengePurpose, userId: string | null) =>
    async (challenge: string) =>
      passkeyRepo.consumeChallenge(
        await hashToken(challenge),
        purpose,
        userId,
        new Date(),
      )

  return {
    enabled,

    async signInOptions() {
      requireEnabled()
      // Usernameless: no allowCredentials, the authenticator offers its own.
      const options = await generateAuthenticationOptions({
        rpID: rpId,
        userVerification: 'required',
        timeout: CHALLENGE_TTL_MS,
      })
      await storeChallenge(options.challenge, 'authenticate', null)
      return options
    },

    // The user id the passkey belongs to. The caller still applies the
    // account gates (exists, not deleted, verified email).
    async verifySignIn(response: unknown): Promise<string> {
      requireEnabled()
      const id = (response as { id?: unknown } | null)?.id
      const row = typeof id === 'string'
        ? await passkeyRepo.findByCredentialIdHash(await hashToken(id))
        : null
      if (!row) throw AppError.of('passkey_invalid')
      let result
      try {
        result = await verifyAuthenticationResponse({
          response: response as AuthResponse,
          expectedChallenge: consume('authenticate', null),
          expectedOrigin: origin,
          expectedRPID: rpId,
          requireUserVerification: true,
          // The library also enforces the counter: a non-zero counter must
          // go up; synced passkeys stay at 0.
          credential: {
            id: row.credentialId,
            publicKey: isoBase64URL.toBuffer(row.publicKey),
            counter: row.counter,
            transports: row.transports as Transports,
          },
        })
      } catch {
        throw AppError.of('passkey_invalid')
      }
      if (!result.verified) throw AppError.of('passkey_invalid')
      await passkeyRepo.recordUse(
        row.id,
        result.authenticationInfo.newCounter,
        new Date(),
      )
      return row.userId
    },

    async registrationOptions(userId: string, signedInAt: Date) {
      requireEnabled()
      // Whoever holds this session could otherwise add their own passkey to
      // someone else's account; a recent sign-in narrows that to minutes.
      if (Date.now() - signedInAt.getTime() > FRESH_LOGIN_MS) {
        throw AppError.of('fresh_login_required')
      }
      const user = await userRepo.findById(userId)
      if (!user?.email) throw AppError.of('user_not_found')
      const existing = await passkeyRepo.listForUser(userId)
      if (existing.length >= MAX_PASSKEYS) {
        throw AppError.of('passkey_limit_reached')
      }
      const options = await generateRegistrationOptions({
        rpName: rpId,
        rpID: rpId,
        userName: user.email,
        // The user handle: the uuid's bytes, no personal data.
        userID: new TextEncoder().encode(userId),
        attestationType: 'none',
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
        },
        excludeCredentials: existing.map((p) => ({
          id: p.credentialId,
          transports: p.transports as Transports,
        })),
        supportedAlgorithmIDs: ALGORITHMS,
        timeout: CHALLENGE_TTL_MS,
      })
      await storeChallenge(options.challenge, 'register', userId)
      return options
    },

    async register(userId: string, response: unknown): Promise<void> {
      requireEnabled()
      let result
      try {
        result = await verifyRegistrationResponse({
          response: response as RegResponse,
          expectedChallenge: consume('register', userId),
          expectedOrigin: origin,
          expectedRPID: rpId,
          requireUserVerification: true,
          supportedAlgorithmIDs: ALGORITHMS,
        })
      } catch {
        throw AppError.of('passkey_invalid')
      }
      if (!result.verified) throw AppError.of('passkey_invalid')
      const info = result.registrationInfo
      if ((await passkeyRepo.listForUser(userId)).length >= MAX_PASSKEYS) {
        throw AppError.of('passkey_limit_reached')
      }
      const credentialIdHash = await hashToken(info.credential.id)
      const already = () => passkeyRepo.findByCredentialIdHash(credentialIdHash)
      if (await already()) throw AppError.of('passkey_already_registered')
      try {
        await passkeyRepo.create({
          id: crypto.randomUUID(),
          userId,
          credentialId: info.credential.id,
          credentialIdHash,
          publicKey: isoBase64URL.fromBuffer(info.credential.publicKey),
          counter: info.credential.counter,
          transports: info.credential.transports ?? [],
          aaguid: info.aaguid,
          backedUp: info.credentialBackedUp,
          createdAt: new Date(),
          lastUsedAt: null,
        })
      } catch (err) {
        // Same shape as TOTP's startSetup: re-read rather than sniff the
        // driver's error code. A parallel register won the unique index.
        if (await already()) throw AppError.of('passkey_already_registered')
        throw err
      }
    },

    async list(userId: string): Promise<PasskeySummary[]> {
      requireEnabled()
      // A service token names no user row: 404 like /users/me.
      if (!(await userRepo.findById(userId))) {
        throw AppError.of('user_not_found')
      }
      return (await passkeyRepo.listForUser(userId)).map((p) => ({
        id: p.id,
        created_at: p.createdAt.toISOString(),
        last_used_at: p.lastUsedAt?.toISOString() ?? null,
        backed_up: p.backedUp,
        aaguid: p.aaguid,
      }))
    },

    async remove(userId: string, id: string): Promise<void> {
      requireEnabled()
      if (!(await passkeyRepo.delete(userId, id))) {
        throw AppError.of('passkey_not_found')
      }
    },
  }
}
