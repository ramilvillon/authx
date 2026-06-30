import { rateLimiter, type Store } from 'hono-rate-limiter'
import { getConnInfo } from 'hono/deno'
import type { Context } from 'hono'
import type { AppEnv } from '../deps.ts'
import type { RateLimitStore } from '../lib/rate-limit-store.ts'

// Resolves a stable client identifier that an unauthenticated caller cannot
// trivially spoof. X-Forwarded-For is attacker-controlled unless the app sits
// behind a trusted proxy, so it is only honored when `trustProxy` is set;
// otherwise we key on the real socket peer address.
function clientKey(c: Context<AppEnv>): string {
  if (c.var.user?.id) return c.var.user.id
  if (c.var.config?.trustProxy) {
    const xff = c.req.header('x-forwarded-for')
    if (xff) return xff.split(',')[0].trim()
  }
  try {
    return getConnInfo(c).remote.address ?? 'unknown'
  } catch {
    // No socket info (e.g. in-process app.request in tests): a single shared
    // bucket is safe — we never fall back to the spoofable XFF header here.
    return 'unknown'
  }
}

// `prefix` namespaces keys so multiple limiters can share one store without
// double-counting the same client (e.g. a global limiter and a stricter
// per-endpoint one).
export function makeRateLimiter(
  store: RateLimitStore,
  opts: { windowMs: number; limit: number; prefix?: string },
) {
  const prefix = opts.prefix ?? 'global'
  return rateLimiter<AppEnv>({
    windowMs: opts.windowMs,
    limit: opts.limit,
    standardHeaders: 'draft-6',
    keyGenerator: (c) => `${prefix}:${clientKey(c)}`,
    // The store only ever sees string keys, so it is independent of the Hono
    // Env; cast past the invariant Env generic here at the commitment point.
    store: store as Store<AppEnv>,
  })
}
