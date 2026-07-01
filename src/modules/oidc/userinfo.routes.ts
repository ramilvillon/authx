import { Hono } from 'hono'
import type { Context } from 'hono'
import type { AppEnv } from '../../deps.ts'
import { verifyWithKeyRing } from '../../lib/jwt.ts'
import { claimsForScopes } from '../../lib/oidc.ts'

function unauthorized(c: Context<AppEnv>) {
  c.header('WWW-Authenticate', 'Bearer')
  return c.json(
    { error: { code: 'unauthorized', message: 'invalid token' } },
    401,
  )
}

async function handler(c: Context<AppEnv>) {
  const header = c.req.header('Authorization')
  if (!header?.startsWith('Bearer ')) return unauthorized(c)
  const token = header.slice('Bearer '.length)
  let claims
  try {
    claims = await verifyWithKeyRing(token, c.var.keySet)
  } catch {
    return unauthorized(c)
  }
  const user = await c.var.userService.getUserRecord(claims.sub)
  if (!user) return unauthorized(c) // M2M / no-user token
  const scopes = claims.oidc_scope
    ? claims.oidc_scope.split(' ')
    : ['openid', 'email']
  return c.json({ sub: user.id, ...claimsForScopes(user, scopes) })
}

const userinfo = new Hono<AppEnv>()
  .get('/userinfo', handler)
  .post('/userinfo', handler)

export default userinfo
