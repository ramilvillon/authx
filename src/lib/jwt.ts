import { decode, sign, verify } from 'hono/jwt'

export type AccessPayload = {
  iss: string
  sub: string
  iat: number
  exp: number
}

export async function signAccessToken(
  opts: {
    sub: string
    issuer: string
    privateKeyPem: string
    kid: string
    ttlSeconds: number
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: opts.issuer,
    sub: opts.sub,
    iat: now,
    exp: now + opts.ttlSeconds,
  }
  // hono/jwt accepts a PEM private key for RS256 and lets us set the kid header.
  // ponytail: kid lives in the JWKS only for now; when rotation lands (Phase 3),
  // switch to a signer that writes the `kid` header.
  return await sign(payload, opts.privateKeyPem, 'RS256')
}

export async function verifyAccessToken(
  token: string,
  publicKeyPem: string,
): Promise<AccessPayload> {
  return await verify(token, publicKeyPem, 'RS256') as AccessPayload
}

export { decode }
