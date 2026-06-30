import { assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

Deno.test('jwks endpoint serves the public signing key', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/.well-known/jwks.json')
  assertEquals(res.status, 200)
  const body = await res.json()
  assertEquals(body.keys.length, 1)
  assertEquals(body.keys[0].use, 'sig')
})

Deno.test('discovery doc points at this issuer and jwks', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/.well-known/openid-configuration')
  const body = await res.json()
  assertEquals(body.issuer, 'http://test.local')
  assertEquals(body.jwks_uri, 'http://test.local/.well-known/jwks.json')
})
