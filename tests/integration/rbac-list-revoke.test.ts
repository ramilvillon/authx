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

function auth(token: string) {
  return { authorization: `Bearer ${token}` }
}

function post(token: string, body: unknown) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...auth(token) },
    body: JSON.stringify(body),
  }
}

// Builds an org + service with one role holding one permission, all through
// the admin API, and returns the ids the listing and revoke routes need.
async function seedRbac(
  app: ReturnType<typeof makeTestApp>['app'],
  token: string,
  key = 'invoices:read',
) {
  const org = await (await app.request(
    '/orgs',
    post(token, { slug: `acme-${crypto.randomUUID()}`, name: 'Acme' }),
  )).json()
  const service = await (await app.request(
    `/orgs/${org.id}/services`,
    post(token, {
      slug: 'billing',
      name: 'Billing',
      audience: `acme-billing-${crypto.randomUUID()}`,
      type: 'public',
      redirectUris: [],
    }),
  )).json()
  const serviceId = service.service?.id ?? service.id
  const role = await (await app.request(
    `/services/${serviceId}/roles`,
    post(token, { name: 'billing-admin' }),
  )).json()
  const permission = await (await app.request(
    `/services/${serviceId}/permissions`,
    post(token, { key }),
  )).json()
  await app.request(
    `/roles/${role.id}/permissions`,
    post(token, { permissionId: permission.id }),
  )
  return { serviceId, role, permission }
}

Deno.test("lists a service's roles with their permissions inlined", async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId, role, permission } = await seedRbac(app, token)

  const res = await app.request(`/services/${serviceId}/roles`, {
    headers: auth(token),
  })
  assertEquals(res.status, 200)
  const body = await res.json()
  assertEquals(body.length, 1)
  assertEquals(body[0].id, role.id)
  assertEquals(body[0].name, 'billing-admin')
  assertEquals(body[0].permissions, [{
    id: permission.id,
    key: 'invoices:read',
  }])
})

Deno.test("lists a service's permissions", async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId, permission } = await seedRbac(app, token)

  const res = await app.request(`/services/${serviceId}/permissions`, {
    headers: auth(token),
  })
  assertEquals(res.status, 200)
  assertEquals(await res.json(), [{ id: permission.id, key: 'invoices:read' }])
})

Deno.test('listing an unknown service is 404', async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  for (const path of ['roles', 'permissions']) {
    const res = await app.request(
      `/services/${crypto.randomUUID()}/${path}`,
      { headers: auth(token) },
    )
    assertEquals(res.status, 404)
    // Assert the code, not just the status: with no route mounted, Hono's own
    // 404 would satisfy the status alone.
    assertEquals((await res.json()).error.code, 'service_not_found')
  }
})

Deno.test('lists the roles held by a user and by a client', async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId, role } = await seedRbac(app, token)
  const user = await (await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'casey@b.com', password: 'pw123456' }),
  })).json()
  await app.request(`/users/${user.id}/roles`, post(token, { roleId: role.id }))
  await app.request(
    `/clients/${serviceId}/roles`,
    post(token, { roleId: role.id }),
  )

  for (
    const path of [`/users/${user.id}/roles`, `/clients/${serviceId}/roles`]
  ) {
    const res = await app.request(path, { headers: auth(token) })
    assertEquals(res.status, 200)
    assertEquals(await res.json(), [{
      id: role.id,
      name: 'billing-admin',
      appServiceId: serviceId,
    }])
  }
})

Deno.test('revoking a permission from a role removes it from the listing', async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId, role, permission } = await seedRbac(app, token)

  const res = await app.request(
    `/roles/${role.id}/permissions/${permission.id}`,
    { method: 'DELETE', headers: auth(token) },
  )
  assertEquals(res.status, 204)
  const roles = await (await app.request(`/services/${serviceId}/roles`, {
    headers: auth(token),
  })).json()
  assertEquals(roles[0].permissions, [])
  // The permission itself still exists; only the grant was removed.
  const perms = await (await app.request(
    `/services/${serviceId}/permissions`,
    { headers: auth(token) },
  )).json()
  assertEquals(perms.length, 1)
})

Deno.test('unassigning a role from a user and from a client empties their listings', async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId, role } = await seedRbac(app, token)
  const user = await (await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'casey@b.com', password: 'pw123456' }),
  })).json()
  await app.request(`/users/${user.id}/roles`, post(token, { roleId: role.id }))
  await app.request(
    `/clients/${serviceId}/roles`,
    post(token, { roleId: role.id }),
  )

  for (
    const path of [
      `/users/${user.id}/roles/${role.id}`,
      `/clients/${serviceId}/roles/${role.id}`,
    ]
  ) {
    assertEquals(
      (await app.request(path, { method: 'DELETE', headers: auth(token) }))
        .status,
      204,
    )
  }
  for (
    const path of [`/users/${user.id}/roles`, `/clients/${serviceId}/roles`]
  ) {
    assertEquals(
      await (await app.request(path, { headers: auth(token) })).json(),
      [],
    )
  }
})

// Same goal state either way: the grant does not exist. Matches
// DELETE /orgs/:id/members/:userId, which is also fire-and-forget.
Deno.test('revoking twice, or revoking a grant that never existed, is still 204', async () => {
  const { app, userRepo } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId, role, permission } = await seedRbac(app, token)
  const del = (path: string) =>
    app.request(path, { method: 'DELETE', headers: auth(token) })

  const path = `/roles/${role.id}/permissions/${permission.id}`
  assertEquals((await del(path)).status, 204)
  assertEquals((await del(path)).status, 204)
  assertEquals(
    (await del(`/users/${crypto.randomUUID()}/roles/${role.id}`)).status,
    204,
  )
  assertEquals(
    (await del(`/clients/${serviceId}/roles/${crypto.randomUUID()}`)).status,
    204,
  )
})

// The seam that matters: a revoke that writes the row but leaves the next
// token's scope untouched would pass every listing assertion above.
Deno.test('a revoked permission is gone from the next token issued', async () => {
  const { app, userRepo, orgRepo, rbacRepo } = makeTestApp()
  const adminToken = await seedPlatformAdmin(userRepo)
  const user = await (await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'casey@b.com', password: 'pw123456' }),
  })).json()
  const audience = await seedDefaultService(orgRepo, user.id)
  await grantPermissions(orgRepo, rbacRepo, audience, user.id, [
    'invoices:read',
  ])
  const scopeOf = async () => {
    const { Authorization } = await authHeader(
      app,
      'casey@b.com',
      'pw123456',
      audience,
    )
    const { payload } = decode(Authorization.slice('Bearer '.length))
    return String((payload as { scope: string }).scope).split(' ')
  }
  assert((await scopeOf()).includes('invoices:read'))

  // Find the ids the way an operator would: through the listings.
  const service = await orgRepo.findServiceByAudience(audience)
  const roles = await (await app.request(`/services/${service!.id}/roles`, {
    headers: auth(adminToken),
  })).json()
  const perm = roles[0].permissions.find((p: { key: string }) =>
    p.key === 'invoices:read'
  )
  assertEquals(
    (await app.request(`/roles/${roles[0].id}/permissions/${perm.id}`, {
      method: 'DELETE',
      headers: auth(adminToken),
    })).status,
    204,
  )

  assertEquals((await scopeOf()).includes('invoices:read'), false)
})

Deno.test('rbac:read can list but not revoke; rbac:write can revoke', async () => {
  const { app, userRepo } = makeTestApp()
  const admin = await seedPlatformAdmin(userRepo)
  const { serviceId, role, permission } = await seedRbac(app, admin)
  const readOnly = await seedPlatformAdmin(
    userRepo,
    PLATFORM_PERMISSIONS.filter((p) => p !== 'rbac:write'),
  )

  assertEquals(
    (await app.request(`/services/${serviceId}/roles`, {
      headers: auth(readOnly),
    })).status,
    200,
  )
  assertEquals(
    (await app.request(`/roles/${role.id}/permissions/${permission.id}`, {
      method: 'DELETE',
      headers: auth(readOnly),
    })).status,
    403,
  )

  const writeOnly = await seedPlatformAdmin(
    userRepo,
    PLATFORM_PERMISSIONS.filter((p) => p !== 'rbac:read'),
  )
  assertEquals(
    (await app.request(`/services/${serviceId}/roles`, {
      headers: auth(writeOnly),
    })).status,
    403,
  )
})
