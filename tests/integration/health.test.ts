import { assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

Deno.test('GET /health returns ok', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/health')
  assertEquals(res.status, 200)
  assertEquals(await res.json(), { status: 'ok' })
})
