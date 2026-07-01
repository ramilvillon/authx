import { createMiddleware } from 'hono/factory'
import type { AppEnv } from '../deps.ts'
import { verifyWithKeyRing } from '../lib/jwt.ts'
import { AppError } from '../lib/errors.ts'

export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Bearer ')) {
    throw AppError.unauthorized('missing bearer token')
  }
  const token = header.slice('Bearer '.length)
  let claims
  try {
    claims = await verifyWithKeyRing(token, c.var.keySet)
  } catch {
    throw AppError.unauthorized('invalid token')
  }
  // An id_token (no scope/client_id) must not authenticate as an access token.
  if (
    typeof claims.client_id !== 'string' || typeof claims.scope !== 'string'
  ) {
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
