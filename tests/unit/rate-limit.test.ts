import { assertEquals } from '@std/assert'
import { Hono } from 'hono'
import type { AppEnv } from '../../src/deps.ts'
import { createMemoryRateLimitStore } from '../../src/lib/rate-limit-store.ts'
import { makeRateLimiter } from '../../src/middleware/rate-limit.ts'

// Builds a tiny app that sits behind `hops` trusted proxies, so the limiter
// keys on the X-Forwarded-For entry those proxies appended.
function trustedProxyApp(limit: number, hops = 1) {
  return new Hono<AppEnv>()
    .use('*', async (c, next) => {
      // deno-lint-ignore no-explicit-any
      c.set('config', { trustProxyHops: hops } as any)
      await next()
    })
    .use(
      '*',
      makeRateLimiter(createMemoryRateLimitStore(), { windowMs: 60000, limit }),
    )
    .get('/', (c) => c.text('ok'))
}

Deno.test('limiter blocks after the configured number of hits', async () => {
  const app = trustedProxyApp(2)
  const hit = () =>
    app.request('/', { headers: { 'x-forwarded-for': '1.1.1.1' } })

  assertEquals((await hit()).status, 200)
  assertEquals((await hit()).status, 200)
  assertEquals((await hit()).status, 429)
})

Deno.test('limiter tracks clients independently by key', async () => {
  const app = trustedProxyApp(1)

  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '1.1.1.1' } }))
      .status,
    200,
  )
  // different client key -> not throttled
  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '2.2.2.2' } }))
      .status,
    200,
  )
  // first client again -> throttled
  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '1.1.1.1' } }))
      .status,
    429,
  )
})

Deno.test('client-prepended X-Forwarded-For entries cannot rotate buckets', async () => {
  // One trusted proxy appends the peer it saw, so only the last entry is ours.
  // The attacker rotates the entries to its left, which must be ignored.
  const app = trustedProxyApp(2, 1)
  const hit = (spoof: string) =>
    app.request('/', { headers: { 'x-forwarded-for': `${spoof}, 9.9.9.9` } })

  assertEquals((await hit('1.2.3.1')).status, 200)
  assertEquals((await hit('1.2.3.2')).status, 200)
  assertEquals((await hit('1.2.3.3')).status, 429)
})

Deno.test('two trusted hops key on the second entry from the right', async () => {
  const app = trustedProxyApp(1, 2)
  // edge -> inner proxy: the edge appended 8.8.8.8, the inner appended itself.
  assertEquals(
    (await app.request('/', {
      headers: { 'x-forwarded-for': '1.2.3.4, 8.8.8.8, 10.0.0.1' },
    })).status,
    200,
  )
  // Same real client behind the same chain, spoofed prefix changed -> throttled.
  assertEquals(
    (await app.request('/', {
      headers: { 'x-forwarded-for': '9.9.9.9, 8.8.8.8, 10.0.0.1' },
    })).status,
    429,
  )
})

Deno.test('a chain shorter than the hop count falls back off the header', async () => {
  // Request bypassed the proxy chain: both callers collapse to the same
  // (socket-peer) bucket instead of getting a free bucket each.
  const app = trustedProxyApp(1, 2)
  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '1.1.1.1' } }))
      .status,
    200,
  )
  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '2.2.2.2' } }))
      .status,
    429,
  )
})

Deno.test('untrusted X-Forwarded-For is ignored (no spoofing)', async () => {
  // No trustProxy: spoofed XFF values all collapse to the same bucket, so
  // rotating the header does NOT grant extra requests.
  const app = new Hono<AppEnv>()
    .use(
      '*',
      makeRateLimiter(createMemoryRateLimitStore(), {
        windowMs: 60000,
        limit: 1,
      }),
    )
    .get('/', (c) => c.text('ok'))

  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '1.1.1.1' } }))
      .status,
    200,
  )
  assertEquals(
    (await app.request('/', { headers: { 'x-forwarded-for': '9.9.9.9' } }))
      .status,
    429,
  )
})
