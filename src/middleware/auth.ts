import { createMiddleware } from 'hono/factory'
import type { AppEnv } from '../deps.ts'
import { verifyWithKeyRing } from '../lib/jwt.ts'
import { AppError } from '../lib/errors.ts'

export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Bearer ')) {
    throw AppError.of('missing_bearer_token')
  }
  const token = header.slice('Bearer '.length)
  let claims
  try {
    claims = await verifyWithKeyRing(token, c.var.keySet)
  } catch {
    throw AppError.of('invalid_token')
  }
  // An id_token (no scope/client_id) must not authenticate as an access token.
  if (
    typeof claims.client_id !== 'string' || typeof claims.scope !== 'string'
  ) {
    throw AppError.of('invalid_token')
  }
  // Authorization is carried by the token's scope claim, not a DB role lookup;
  // email is the only thing we fetch (and only if the subject still exists).
  const user = await c.var.userService.getById(claims.sub).catch(() => null)
  // A token whose subject is a user stays valid only while that user exists, so
  // deleting an account revokes its in-flight access tokens. Client-credentials
  // tokens say sub_type 'service' (`sub` is an app-service id) and tokens minted
  // before this claim existed say nothing — neither requires a user row.
  if (claims.sub_type === 'user' && !user) throw AppError.of('invalid_token')
  c.set('user', {
    id: claims.sub,
    email: user?.email ?? '',
    permissions: claims.scope ? claims.scope.split(' ') : [],
    org: claims.org,
    aud: claims.aud,
  })
  await next()
})
