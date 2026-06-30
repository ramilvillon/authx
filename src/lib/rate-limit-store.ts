import type { Store } from 'hono-rate-limiter'

export type RateLimitStore = Store

// A minimal in-memory fixed-window store implementing hono-rate-limiter's
// Store contract. Default store when no REDIS_URL is configured.
export function createMemoryRateLimitStore(): RateLimitStore {
  const hits = new Map<string, { count: number; resetAt: number }>()
  let windowMs = 60000

  return {
    init(options) {
      windowMs = options.windowMs
    },
    increment(key) {
      const now = Date.now()
      const entry = hits.get(key)
      if (!entry || entry.resetAt <= now) {
        const fresh = { count: 1, resetAt: now + windowMs }
        hits.set(key, fresh)
        return { totalHits: 1, resetTime: new Date(fresh.resetAt) }
      }
      entry.count++
      return { totalHits: entry.count, resetTime: new Date(entry.resetAt) }
    },
    decrement(key) {
      const entry = hits.get(key)
      if (entry && entry.count > 0) entry.count--
    },
    resetKey(key) {
      hits.delete(key)
    },
  }
}

export function createRedisRateLimitStore(_redisUrl: string): RateLimitStore {
  // The Redis-backed store is the optional production swap: it implements the
  // same Store contract across instances. Wire a redis client here.
  throw new Error('Redis rate-limit store not configured in this environment')
}
