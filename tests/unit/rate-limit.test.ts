import { assertEquals } from '@std/assert'
import { Hono } from 'hono'
import type { AppEnv } from '../../src/deps.ts'
import { createMemoryRateLimitStore } from '../../src/lib/rate-limit-store.ts'
import { makeRateLimiter } from '../../src/middleware/rate-limit.ts'

// Builds a tiny app that trusts proxy headers, so the limiter keys on the
// X-Forwarded-For hop (the trusted-proxy deployment path).
function trustedProxyApp(limit: number) {
  return new Hono<AppEnv>()
    .use('*', async (c, next) => {
      // deno-lint-ignore no-explicit-any
      c.set('config', { trustProxy: true } as any)
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
