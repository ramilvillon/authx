import { rateLimiter, type Store } from 'hono-rate-limiter'
import { getConnInfo } from 'hono/deno'
import type { Context } from 'hono'
import type { AppEnv } from '../deps.ts'
import type { RateLimitStore } from '../lib/rate-limit-store.ts'
import { ERRORS } from '../lib/errors.ts'

// Resolves a stable client identifier that an unauthenticated caller cannot
// trivially spoof. Reverse proxies *append* the peer they observed to
// X-Forwarded-For, so the left-most entries are whatever the client sent and
// stay attacker-controlled; only the last `trustProxyHops` entries were
// written by our own proxies. We therefore count from the right: with N
// trusted hops the entry at -N is the address the outermost trusted proxy
// observed, and everything left of it is ignored. A chain shorter than the
// configured hop count means the request did not traverse the expected proxy
// chain, so we fall back to the real socket peer address.
function clientKey(c: Context<AppEnv>): string {
  if (c.var.user?.id) return c.var.user.id
  const hops = c.var.config?.trustProxyHops ?? 0
  if (hops > 0) {
    const chain = c.req.header('x-forwarded-for')?.split(',') ?? []
    // `at()` returns undefined when the chain is shorter than `hops`.
    const addr = chain.at(-hops)?.trim()
    if (addr) return addr
  }
  try {
    return getConnInfo(c).remote.address ?? 'unknown'
  } catch {
    // No socket info (e.g. in-process app.request in tests): a single shared
    // bucket is safe — we never fall back to the spoofable XFF header here.
    return 'unknown'
  }
}

const TOKEN_ENDPOINTS = new Set(['/oauth/token', '/oauth/revoke'])

// `prefix` namespaces keys so multiple limiters can share one store without
// double-counting the same client (e.g. a global limiter and a stricter
// per-endpoint one).
export function makeRateLimiter(
  store: RateLimitStore,
  opts: {
    windowMs: number
    limit: number
    prefix?: string
    // Narrows what the bucket counts. Without this a limiter charges every
    // request, so ordinary use spends the budget that is meant to stop abuse.
    countOnly?: (status: number) => boolean
  },
) {
  const prefix = opts.prefix ?? 'global'
  return rateLimiter<AppEnv>({
    windowMs: opts.windowMs,
    limit: opts.limit,
    standardHeaders: 'draft-6',
    // The library's default body is plain text, which OAuth client libraries
    // reject as the wrong content type. JSON instead, in the shape the path
    // already answers errors in: flat RFC 6749 on the token endpoints, the
    // catalogue's everywhere else.
    message: (c: Context<AppEnv>) => {
      const { message } = ERRORS.rate_limited
      return TOKEN_ENDPOINTS.has(c.req.path)
        ? { error: 'rate_limited', error_description: message }
        : { error: { code: 'rate_limited', message } }
    },
    skipSuccessfulRequests: opts.countOnly !== undefined,
    requestWasSuccessful: (c) => !opts.countOnly!(c.res.status),
    keyGenerator: (c) => `${prefix}:${clientKey(c)}`,
    // The store only ever sees string keys, so it is independent of the Hono
    // Env; cast past the invariant Env generic here at the commitment point.
    store: store as Store<AppEnv>,
  })
}
