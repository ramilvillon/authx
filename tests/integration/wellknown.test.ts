import { assert, assertEquals } from '@std/assert'
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

Deno.test('discovery advertises OIDC endpoints, scopes, and claims', async () => {
  const { app } = makeTestApp()
  const doc = await (await app.request('/.well-known/openid-configuration'))
    .json()
  assertEquals(doc.userinfo_endpoint, `${doc.issuer}/oauth/userinfo`)
  assertEquals(doc.response_types_supported, ['code'])
  assertEquals(doc.subject_types_supported, ['public'])
  assertEquals(doc.scopes_supported, ['openid', 'email', 'profile'])
  assertEquals(doc.code_challenge_methods_supported, ['S256'])
  assert(doc.claims_supported.includes('email_verified'))
  assert(doc.claims_supported.includes('name'))
})
