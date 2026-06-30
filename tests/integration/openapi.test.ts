import { assert, assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

Deno.test('serves an OpenAPI document', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/openapi')
  assertEquals(res.status, 200)
  const doc = await res.json()
  assert(doc.openapi.startsWith('3'))
  assert(doc.paths['/users'])
})

Deno.test('documents every mounted route', async () => {
  const { app } = makeTestApp()
  const doc = await (await app.request('/openapi')).json()

  // All registered routes should appear in the spec, not just POST /users.
  const expected: Array<[string, string]> = [
    ['/users', 'post'],
    ['/users/me', 'get'],
    ['/users', 'get'],
    ['/users/{id}', 'get'],
    ['/users/{id}', 'patch'],
    ['/users/{id}', 'delete'],
    ['/oauth/token', 'post'],
    ['/oauth/revoke', 'post'],
    ['/oauth/google', 'get'],
  ]
  for (const [path, method] of expected) {
    assert(doc.paths[path]?.[method], `missing ${method.toUpperCase()} ${path}`)
  }
})

Deno.test('declares a bearer auth scheme and tags protected routes', async () => {
  const { app } = makeTestApp()
  const doc = await (await app.request('/openapi')).json()

  assertEquals(doc.components?.securitySchemes?.bearerAuth?.scheme, 'bearer')
  // A protected route should reference the scheme.
  assert(
    doc.paths['/users/me'].get.security?.some(
      (s: Record<string, unknown>) => 'bearerAuth' in s,
    ),
    'GET /users/me should require bearerAuth',
  )
})

Deno.test('serves Scalar docs page', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/docs')
  assertEquals(res.status, 200)
  assert((res.headers.get('content-type') ?? '').includes('text/html'))
})
