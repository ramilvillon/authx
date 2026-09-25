import { ciEquals, duplicateKey } from '../../lib/inmemory.ts'

export type PasskeyRecord = {
  id: string
  userId: string
  credentialId: string // base64url, case-sensitive
  credentialIdHash: string // sha256 hex of credentialId
  publicKey: string // COSE key, base64url
  counter: number
  transports: string[]
  aaguid: string
  backedUp: boolean
  createdAt: Date
  lastUsedAt: Date | null
}
export type ChallengePurpose = 'register' | 'authenticate'
export type PasskeyRepository = {
  create(row: PasskeyRecord): Promise<void>
  findByCredentialIdHash(hash: string): Promise<PasskeyRecord | null>
  listForUser(userId: string): Promise<PasskeyRecord[]>
  recordUse(id: string, counter: number, at: Date): Promise<void>
  delete(userId: string, id: string): Promise<boolean>
  createChallenge(c: {
    challengeHash: string
    purpose: ChallengePurpose
    userId: string | null
    expiresAt: Date
  }): Promise<void>
  consumeChallenge(
    challengeHash: string,
    purpose: ChallengePurpose,
    userId: string | null,
    now: Date,
  ): Promise<boolean>
  deleteExpiredChallengesBefore(cutoff: Date): Promise<number>
  deleteAllForUser(userId: string): Promise<number>
  // Passkeys only, not the user's challenges: used on password reset/change,
  // where the point is revoking credentials, not clearing in-flight
  // ceremonies (which expire on their own in 5 minutes anyway).
  deleteAllPasskeysForUser(userId: string): Promise<number>
}

type ChallengeRow = {
  challengeHash: string
  purpose: ChallengePurpose
  userId: string | null
  expiresAt: Date
  consumedAt: Date | null
}

// In-memory test double. Mirror behavior in passkey.repository.drizzle.ts.
// consumeChallenge is ONE conditional update in MySQL: two parallel sign-ins
// with the same challenge cannot both win.
export function createInMemoryPasskeyRepository(): PasskeyRepository {
  let rows: PasskeyRecord[] = []
  let challenges: ChallengeRow[] = []
  const copy = (r: PasskeyRecord) => ({ ...r, transports: [...r.transports] })
  return {
    create(row) {
      if (
        rows.some((r) => ciEquals(r.credentialIdHash, row.credentialIdHash))
      ) {
        return Promise.reject(
          duplicateKey('passkeys', 'credential_id_hash', row.credentialIdHash),
        )
      }
      if (rows.some((r) => r.id === row.id)) {
        return Promise.reject(duplicateKey('passkeys', 'PRIMARY', row.id))
      }
      rows.push(copy(row))
      return Promise.resolve()
    },
    findByCredentialIdHash(hash) {
      const r = rows.find((r) => ciEquals(r.credentialIdHash, hash))
      return Promise.resolve(r ? copy(r) : null)
    },
    listForUser(userId) {
      return Promise.resolve(rows.filter((r) => r.userId === userId).map(copy))
    },
    recordUse(id, counter, at) {
      const r = rows.find((r) => r.id === id)
      if (r) Object.assign(r, { counter, lastUsedAt: at })
      return Promise.resolve()
    },
    delete(userId, id) {
      const before = rows.length
      rows = rows.filter((r) => !(r.id === id && r.userId === userId))
      return Promise.resolve(rows.length < before)
    },
    createChallenge(c) {
      if (challenges.some((x) => ciEquals(x.challengeHash, c.challengeHash))) {
        return Promise.reject(
          duplicateKey(
            'webauthn_challenges',
            'challenge_hash',
            c.challengeHash,
          ),
        )
      }
      challenges.push({ ...c, consumedAt: null })
      return Promise.resolve()
    },
    consumeChallenge(challengeHash, purpose, userId, now) {
      const c = challenges.find((x) =>
        ciEquals(x.challengeHash, challengeHash) && x.purpose === purpose &&
        x.userId === userId && !x.consumedAt && x.expiresAt > now
      )
      if (!c) return Promise.resolve(false)
      c.consumedAt = now
      return Promise.resolve(true)
    },
    deleteExpiredChallengesBefore(cutoff) {
      const before = challenges.length
      challenges = challenges.filter((c) => c.expiresAt >= cutoff)
      return Promise.resolve(before - challenges.length)
    },
    deleteAllForUser(userId) {
      const before = rows.length + challenges.length
      rows = rows.filter((r) => r.userId !== userId)
      challenges = challenges.filter((c) => c.userId !== userId)
      return Promise.resolve(before - rows.length - challenges.length)
    },
    deleteAllPasskeysForUser(userId) {
      const before = rows.length
      rows = rows.filter((r) => r.userId !== userId)
      return Promise.resolve(before - rows.length)
    },
  }
}
