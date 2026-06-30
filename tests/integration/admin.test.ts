import { assert, assertEquals } from '@std/assert'
import { decode } from 'hono/jwt'
import {
  authHeader,
  grantPermissions,
  makeTestApp,
  PLATFORM_PERMISSIONS,
  seedDefaultService,
  seedPlatformAdmin,
} from '../helpers.ts'

function json(token: string, body: unknown) {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  }
}

Deno.test('admin can create an org', async () => {
  const ctx = makeTestApp()
  const token = await seedPlatformAdmin()
  const res = await ctx.app.request(
    '/orgs',
    json(token, { slug: 'acme', name: 'Acme' }),
  )
  assertEquals(res.status, 201)
  assertEquals((await res.json()).slug, 'acme')
})

Deno.test('missing permission -> 403', async () => {
  const ctx = makeTestApp()
  // Token without orgs:write.
  const token = await seedPlatformAdmin(
    PLATFORM_PERMISSIONS.filter((p) => p !== 'orgs:write'),
  )
  const res = await ctx.app.request(
    '/orgs',
    json(token, { slug: 'acme', name: 'Acme' }),
  )
  assertEquals(res.status, 403)
})

Deno.test('a service-scoped token with a colliding permission cannot reach the admin API', async () => {
  const ctx = makeTestApp()
  // A normal user in a normal service whose RBAC happens to define 'orgs:write'.
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'attacker@evil.com', password: 'pw123456' }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id, 'evil')
  await grantPermissions(ctx.orgRepo, ctx.rbacRepo, audience, user.id, [
    'orgs:write',
  ])
  const { Authorization } = await authHeader(
    ctx.app,
    'attacker@evil.com',
    'pw123456',
    audience,
  )
  // Scope carries orgs:write, but the token's aud is 'evil', not 'platform'.
  const res = await ctx.app.request('/orgs', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: Authorization,
    },
    body: JSON.stringify({ slug: 'acme', name: 'Acme' }),
  })
  assertEquals(res.status, 403)
})

Deno.test('register confidential service returns a one-time client secret', async () => {
  const ctx = makeTestApp()
  const token = await seedPlatformAdmin()
  const org = await (await ctx.app.request(
    '/orgs',
    json(token, { slug: 'acme', name: 'Acme' }),
  )).json()
  const res = await ctx.app.request(
    `/orgs/${org.id}/services`,
    json(token, {
      slug: 'billing',
      name: 'Billing',
      audience: 'acme-billing',
      type: 'confidential',
    }),
  )
  assertEquals(res.status, 201)
  const body = await res.json()
  assertEquals(body.service.audience, 'acme-billing')
  assert(typeof body.clientSecret === 'string' && body.clientSecret.length > 0)
})

Deno.test('end-to-end: grant a role and see it in the token scope', async () => {
  const ctx = makeTestApp()
  const token = await seedPlatformAdmin()

  const org = await (await ctx.app.request(
    '/orgs',
    json(token, { slug: 'acme', name: 'Acme' }),
  )).json()
  const { service } = await (await ctx.app.request(
    `/orgs/${org.id}/services`,
    json(token, {
      slug: 'billing',
      name: 'Billing',
      audience: 'acme-billing',
      type: 'public',
    }),
  )).json()

  // Register a normal user and make them a member of the org.
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'member@acme.com', password: 'pw123456' }),
  })).json()
  assertEquals(
    (await ctx.app.request(
      `/orgs/${org.id}/members`,
      json(token, { userId: user.id }),
    )).status,
    204,
  )

  // Define a role + permission, grant, and assign to the user.
  const role = await (await ctx.app.request(
    `/services/${service.id}/roles`,
    json(token, { name: 'admin' }),
  )).json()
  const perm = await (await ctx.app.request(
    `/services/${service.id}/permissions`,
    json(token, { key: 'billing:read' }),
  )).json()
  assertEquals(
    (await ctx.app.request(
      `/roles/${role.id}/permissions`,
      json(token, { permissionId: perm.id }),
    )).status,
    204,
  )
  assertEquals(
    (await ctx.app.request(
      `/users/${user.id}/roles`,
      json(token, { roleId: role.id }),
    )).status,
    204,
  )

  // The user's token for this service now carries the granted scope.
  const { Authorization } = await authHeader(
    ctx.app,
    'member@acme.com',
    'pw123456',
    'acme-billing',
  )
  const { payload } = decode(Authorization.slice('Bearer '.length))
  assertEquals(payload.scope, 'billing:read')
})
