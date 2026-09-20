import { assertEquals } from '@std/assert'
import { makeTestApp, seedPlatformAdmin } from '../helpers.ts'

// MySQL enforces these uniquely; the in-memory repositories are Maps and
// enforce nothing. Without an explicit check the duplicate insert reaches the
// database, raises a raw driver error, and falls through onError as a 500
// `internal` -- so a caller gets "something broke" for a request that is simply
// a conflict. These assert the conflict is reported as one.
function post(token: string, body: unknown) {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  }
}

async function orgAndService(
  app: ReturnType<typeof makeTestApp>['app'],
  token: string,
) {
  const org = await (await app.request(
    '/orgs',
    post(token, {
      slug: 'acme',
      name: 'Acme',
    }),
  )).json()
  const svc = await (await app.request(
    `/orgs/${org.id}/services`,
    post(token, {
      slug: 'app',
      name: 'App',
      audience: 'acme-app',
      type: 'public',
      redirectUris: [],
    }),
  )).json()
  return { orgId: org.id, serviceId: svc.service.id }
}

Deno.test('creating an org with a taken slug is a conflict, not a server error', async () => {
  const { userRepo, app } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const body = { slug: 'acme', name: 'Acme' }

  assertEquals((await app.request('/orgs', post(token, body))).status, 201)
  const res = await app.request('/orgs', post(token, body))

  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'org_slug_taken')
})

Deno.test('registering a service with a taken audience is a conflict', async () => {
  const { userRepo, app } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { orgId } = await orgAndService(app, token)

  // The audience is globally unique: it is what an access token's `aud` claim
  // carries, so two services sharing one would be indistinguishable to
  // requireAuth.
  const res = await app.request(
    `/orgs/${orgId}/services`,
    post(token, {
      slug: 'other',
      name: 'Other',
      audience: 'acme-app',
      type: 'public',
      redirectUris: [],
    }),
  )

  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'service_audience_taken')
})

Deno.test('creating a role with a name already used in that service is a conflict', async () => {
  const { userRepo, app } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId } = await orgAndService(app, token)

  assertEquals(
    (await app.request(
      `/services/${serviceId}/roles`,
      post(token, { name: 'editor' }),
    )).status,
    201,
  )
  const res = await app.request(
    `/services/${serviceId}/roles`,
    post(token, { name: 'editor' }),
  )

  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'role_name_taken')
})

Deno.test('creating a permission with a key already used in that service is a conflict', async () => {
  const { userRepo, app } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { serviceId } = await orgAndService(app, token)

  assertEquals(
    (await app.request(
      `/services/${serviceId}/permissions`,
      post(token, { key: 'docs:read' }),
    )).status,
    201,
  )
  const res = await app.request(
    `/services/${serviceId}/permissions`,
    post(token, { key: 'docs:read' }),
  )

  assertEquals(res.status, 409)
  assertEquals((await res.json()).error.code, 'permission_key_taken')
})

Deno.test('the same name in a DIFFERENT service is not a conflict', async () => {
  const { userRepo, app } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { orgId, serviceId } = await orgAndService(app, token)
  const second = await (await app.request(
    `/orgs/${orgId}/services`,
    post(token, {
      slug: 'two',
      name: 'Two',
      audience: 'acme-two',
      type: 'public',
      redirectUris: [],
    }),
  )).json()

  // The constraint is (app_service_id, name), not name alone -- scoping the
  // check too widely would break per-service RBAC.
  await app.request(
    `/services/${serviceId}/roles`,
    post(token, { name: 'editor' }),
  )
  const res = await app.request(
    `/services/${second.service.id}/roles`,
    post(token, { name: 'editor' }),
  )

  assertEquals(res.status, 201)
})

// Every char column is utf8mb4_0900_ai_ci, so the UNIQUE indexes above collapse
// case: 'ACME' and 'acme' are one slug to the database. The doubles compared
// with ===, so in this mode the second insert looked free and the suite could
// have pinned a 201 that MySQL would refuse.
Deno.test('a slug, audience, role name or permission key differing only in case is still taken', async () => {
  const { userRepo, app } = makeTestApp()
  const token = await seedPlatformAdmin(userRepo)
  const { orgId, serviceId } = await orgAndService(app, token)

  const org = await app.request(
    '/orgs',
    post(token, { slug: 'ACME', name: 'A' }),
  )
  assertEquals(org.status, 409)
  assertEquals((await org.json()).error.code, 'org_slug_taken')

  const svc = await app.request(
    `/orgs/${orgId}/services`,
    post(token, {
      slug: 'other',
      name: 'Other',
      audience: 'ACME-APP',
      type: 'public',
      redirectUris: [],
    }),
  )
  assertEquals(svc.status, 409)
  assertEquals((await svc.json()).error.code, 'service_audience_taken')

  await app.request(
    `/services/${serviceId}/roles`,
    post(token, { name: 'editor' }),
  )
  const role = await app.request(
    `/services/${serviceId}/roles`,
    post(token, { name: 'Editor' }),
  )
  assertEquals(role.status, 409)
  assertEquals((await role.json()).error.code, 'role_name_taken')

  await app.request(
    `/services/${serviceId}/permissions`,
    post(token, { key: 'docs:read' }),
  )
  const perm = await app.request(
    `/services/${serviceId}/permissions`,
    post(token, { key: 'Docs:Read' }),
  )
  assertEquals(perm.status, 409)
  assertEquals((await perm.json()).error.code, 'permission_key_taken')
})
