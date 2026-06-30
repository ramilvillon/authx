import { createMiddleware } from 'hono/factory'
import type { AppEnv } from '../deps.ts'
import { AppError } from '../lib/errors.ts'

export function requirePermission(permission: string) {
  return createMiddleware<AppEnv>(async (c, next) => {
    if (!c.var.user.permissions.includes(permission)) {
      // Generic message: don't disclose which permission the route requires.
      throw AppError.forbidden('forbidden')
    }
    await next()
  })
}

export function requireSelfOrPermission(paramName: string, permission: string) {
  return createMiddleware<AppEnv>(async (c, next) => {
    const isSelf = c.req.param(paramName) === c.var.user.id
    if (!isSelf && !c.var.user.permissions.includes(permission)) {
      throw AppError.forbidden('not allowed')
    }
    await next()
  })
}
