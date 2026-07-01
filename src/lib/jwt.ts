import { decode, sign, verify } from 'hono/jwt'
import { type KeySet, privatePemToSigningJwk } from './keys.ts'

export type AccessPayload = {
  iss: string
  sub: string
  iat: number
  exp: number
}
export type AccessClaims = AccessPayload & {
  aud: string
  org: string
  scope: string
  client_id: string
}

export async function signAccessToken(
  opts: {
    sub: string
    issuer: string
    privateKeyPem: string
    kid: string
    ttlSeconds: number
    aud: string
    org: string
    scope: string
    clientId: string
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: opts.issuer,
    sub: opts.sub,
    aud: opts.aud,
    org: opts.org,
    scope: opts.scope,
    client_id: opts.clientId,
    iat: now,
    exp: now + opts.ttlSeconds,
  }
  // Sign with a JWK carrying alg+kid so the `kid` lands in the JWT header.
  // ponytail: converts PEM→JWK per call; precompute on the key ring if signing
  // throughput ever matters.
  const signingJwk = await privatePemToSigningJwk(opts.privateKeyPem, opts.kid)
  return await sign(payload, signingJwk, 'RS256')
}

export async function verifyAccessToken(
  token: string,
  publicKeyPem: string,
): Promise<AccessClaims> {
  return await verify(token, publicKeyPem, 'RS256') as AccessClaims
}

// Verify against the key ring: pick the key by the token's `kid`, or the active
// key when a token carries no kid (pre-rotation tokens). Unknown kid → reject.
export async function verifyWithKeyRing(
  token: string,
  keySet: KeySet,
): Promise<AccessClaims> {
  const { header } = decode(token) as { header: { kid?: string } }
  const publicKeyPem = header.kid
    ? keySet.byKid.get(header.kid)
    : keySet.publicKeyPem
  if (!publicKeyPem) throw new Error('unknown signing key')
  return await verify(token, publicKeyPem, 'RS256') as AccessClaims
}

export { decode }
