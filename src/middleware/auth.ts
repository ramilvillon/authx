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
  let sub: string
  try {
    const payload = await verifyAccessToken(token, c.var.config.jwtSecret)
    sub = payload.sub
  } catch {
    throw AppError.unauthorized('invalid token')
  }
  const user = await c.var.authService.resolveUser(sub)
  c.set('user', user)
  await next()
})
