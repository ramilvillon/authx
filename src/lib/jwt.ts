import { sign, verify } from 'hono/jwt'

export type AccessPayload = { sub: string; exp: number }

export async function signAccessToken(
  opts: { sub: string; secret: string; ttlSeconds: number },
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + opts.ttlSeconds
  return await sign({ sub: opts.sub, exp }, opts.secret)
}

export async function verifyAccessToken(
  token: string,
  secret: string,
): Promise<AccessPayload> {
  return await verify(token, secret, 'HS256') as AccessPayload
}
