import { assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

Deno.test('POST /users registers a user', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
  assertEquals(res.status, 201)
  const body = await res.json()
  assertEquals(body.email, 'a@b.com')
})

Deno.test('POST /users validation error -> 400', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'nope', password: 'x' }),
  })
  assertEquals(res.status, 400)
})
