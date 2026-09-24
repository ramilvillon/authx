import type { RefreshTokenRepository } from '../modules/auth/token.repository.ts'
import type { SessionRepository } from '../modules/auth/session.repository.ts'
import type { AuthCodeRepository } from '../modules/auth/authcode.repository.ts'
import type { VerificationTokenRepository } from '../modules/verification/verification.repository.ts'
import type { PasskeyRepository } from '../modules/passkeys/passkey.repository.ts'

export type PrunableRepos = {
  tokenRepo: RefreshTokenRepository
  sessionRepo: SessionRepository
  authCodeRepo: AuthCodeRepository
  verificationRepo: VerificationTokenRepository
  passkeyRepo: Pick<PasskeyRepository, 'deleteExpiredChallengesBefore'>
}

export type PruneCounts = {
  refreshTokens: number
  sessions: number
  authorizationCodes: number
  emailVerificationTokens: number
  webauthnChallenges: number
}

// Deletes rows that expired before `cutoff`. Nothing else in the codebase ever
// removed these, so they grew with uptime forever.
//
// `cutoff` is deliberately a retention boundary rather than `now`. Two paths
// read an already-dead row on purpose:
//
//   refreshGrant           checks revokedAt BEFORE expiry, so replaying a
//                          stolen token revokes the whole family
//   exchangeAuthorizationCode  checks consumedAt, so replaying a code does too
//
// Delete those rows on expiry and a replay degrades to an unremarkable 401
// with no family revocation -- theft detection stops working, silently and
// with every test still green. The retention window IS the detection window.
//
// Pruning on expiresAt is already TTL-relative: a row minted with a 90-day TTL
// carries a 90-day expiresAt, so "expired more than N ago" holds whatever
// REFRESH_TOKEN_TTL is set to, and one knob covers every table.
export async function pruneExpired(
  repos: PrunableRepos,
  cutoff: Date,
): Promise<PruneCounts> {
  const [
    refreshTokens,
    sessions,
    authorizationCodes,
    emailVerificationTokens,
    webauthnChallenges,
  ] = await Promise.all([
    repos.tokenRepo.deleteExpiredBefore(cutoff),
    repos.sessionRepo.deleteExpiredBefore(cutoff),
    repos.authCodeRepo.deleteExpiredBefore(cutoff),
    repos.verificationRepo.deleteExpiredBefore(cutoff),
    repos.passkeyRepo.deleteExpiredChallengesBefore(cutoff),
  ])
  return {
    refreshTokens,
    sessions,
    authorizationCodes,
    emailVerificationTokens,
    webauthnChallenges,
  }
}

// CLI: `deno task db:prune`. A one-shot command rather than an in-process
// timer, so it does not multiply across replicas or stop when a pod restarts.
// Schedule it wherever cron lives (the repo already runs a weekly e2e job).
if (import.meta.main) {
  const { loadConfig } = await import('../config.ts')
  const { createDb } = await import('./client.ts')
  const { createLogger } = await import('../lib/logger.ts')
  const { createDrizzleRefreshTokenRepository } = await import(
    '../modules/auth/token.repository.drizzle.ts'
  )
  const { createDrizzleSessionRepository } = await import(
    '../modules/auth/session.repository.drizzle.ts'
  )
  const { createDrizzleAuthCodeRepository } = await import(
    '../modules/auth/authcode.repository.drizzle.ts'
  )
  const { createDrizzleVerificationTokenRepository } = await import(
    '../modules/verification/verification.repository.drizzle.ts'
  )
  const { createDrizzlePasskeyRepository } = await import(
    '../modules/passkeys/passkey.repository.drizzle.ts'
  )

  const { createDeps } = await import('../deps.ts')
  const config = loadConfig(Deno.env.toObject())
  const logger = createLogger(config)
  const { db } = createDb(config)
  const deps = await createDeps(config, db)
  const cutoff = new Date(Date.now() - config.pruneRetention * 1000)
  const purgeCutoff = new Date(Date.now() - config.accountPurgeGrace * 1000)
  const purgedAccounts = await deps.userService.purgeDeletedBefore(purgeCutoff)
  const counts = await pruneExpired({
    tokenRepo: createDrizzleRefreshTokenRepository(db),
    sessionRepo: createDrizzleSessionRepository(db),
    authCodeRepo: createDrizzleAuthCodeRepository(db),
    verificationRepo: createDrizzleVerificationTokenRepository(db),
    passkeyRepo: createDrizzlePasskeyRepository(db),
  }, cutoff)
  logger.info(
    {
      cutoff: cutoff.toISOString(),
      purgeCutoff: purgeCutoff.toISOString(),
      purgedAccounts,
      ...counts,
    },
    'pruned expired rows and purged deleted accounts',
  )
  Deno.exit(0)
}
