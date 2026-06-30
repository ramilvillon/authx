import { assertEquals } from '@std/assert'
import { hc } from 'hono/client'
import type { AppType } from '../../src/app.ts'
import { makeTestApp } from '../helpers.ts'

Deno.test('typed client hits /health', async () => {
  const { app } = makeTestApp()
  const client = hc<AppType>('http://local.test', { fetch: app.request })
  const res = await client.health.$get()
  assertEquals(res.status, 200)
  assertEquals(await res.json(), { status: 'ok' })
})
