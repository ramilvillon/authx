import { createMiddleware } from 'hono/factory'
import type { AppEnv } from '../deps.ts'
import { verifyAccessToken } from '../lib/jwt.ts'
import { AppError } from '../lib/errors.ts'

export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Bearer ')) {
    throw AppError.unauthorized('missing bearer token')
  }
  const token = header.slice('Bearer '.length)
  let claims
  try {
    claims = await verifyAccessToken(token, c.var.keySet.publicKeyPem)
  } catch {
    throw AppError.unauthorized('invalid token')
  }
  // Authorization is carried by the token's scope claim, not a DB role lookup;
  // email is the only thing we fetch (and only if the subject still exists).
  const user = await c.var.userService.getById(claims.sub).catch(() => null)
  c.set('user', {
    id: claims.sub,
    email: user?.email ?? '',
    permissions: claims.scope ? claims.scope.split(' ') : [],
    org: claims.org,
    aud: claims.aud,
  })
  await next()
})
