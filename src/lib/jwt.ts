import { decode, sign, verify } from 'hono/jwt'

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
  return await sign(payload, opts.privateKeyPem, 'RS256')
}

export async function verifyAccessToken(
  token: string,
  publicKeyPem: string,
): Promise<AccessClaims> {
  return await verify(token, publicKeyPem, 'RS256') as AccessClaims
}

export { decode }
