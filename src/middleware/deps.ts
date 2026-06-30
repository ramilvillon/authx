import { createMiddleware } from 'hono/factory'
import type { Deps } from '../deps.ts'

export function injectDeps(deps: Deps) {
  return createMiddleware(async (c, next) => {
    for (const [key, value] of Object.entries(deps)) {
      c.set(key as keyof Deps, value as never)
    }
    await next()
  })
}
