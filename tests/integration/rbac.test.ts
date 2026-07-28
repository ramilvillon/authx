import { assertEquals } from '@std/assert'
import {
  authHeader,
  grantPermissions,
  makeTestApp,
  seedDefaultService,
  seedPlatformAdmin,
} from '../helpers.ts'

async function registerAndId(
  app: ReturnType<typeof makeTestApp>['app'],
  email: string,
) {
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'pw123456' }),
  })
  return (await res.json()).id as string
}

Deno.test('non-admin cannot list users', async () => {
  const { app, orgRepo } = makeTestApp()
  const userId = await registerAndId(app, 'a@b.com')
  const audience = await seedDefaultService(orgRepo, userId)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'pw123456',
    audience,
  )
  assertEquals(
    (await app.request('/users', { headers: { Authorization } })).status,
    403,
  )
})

Deno.test('platform admin can list users', async () => {
  const { app } = makeTestApp()
  const Authorization = `Bearer ${await seedPlatformAdmin(['users:list'])}`
  assertEquals(
    (await app.request('/users', { headers: { Authorization } })).status,
    200,
  )
})

// Permission keys are per-service, so the same key defined inside a tenant
// service must not authorize the platform-global user directory.
Deno.test('tenant-service token with users:list cannot list users', async () => {
  const { app, orgRepo, rbacRepo } = makeTestApp()
  const id = await registerAndId(app, 'admin@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  await grantPermissions(orgRepo, rbacRepo, audience, id, ['users:list'])
  const { Authorization } = await authHeader(
    app,
    'admin@b.com',
    'pw123456',
    audience,
  )
  assertEquals(
    (await app.request('/users', { headers: { Authorization } })).status,
    403,
  )
})

Deno.test('user can read self but not others; only a platform admin reads others', async () => {
  const { app, orgRepo, rbacRepo } = makeTestApp()
  const aId = await registerAndId(app, 'a@b.com')
  const bId = await registerAndId(app, 'b@b.com')
  const audience = await seedDefaultService(orgRepo, aId)
  const aAuth = await authHeader(app, 'a@b.com', 'pw123456', audience)
  assertEquals(
    (await app.request(`/users/${aId}`, {
      headers: { Authorization: aAuth.Authorization },
    })).status,
    200,
  )
  assertEquals(
    (await app.request(`/users/${bId}`, {
      headers: { Authorization: aAuth.Authorization },
    })).status,
    403,
  )

  // users:read:any granted inside the tenant service stays powerless here.
  await grantPermissions(orgRepo, rbacRepo, audience, aId, ['users:read:any'])
  const aAdmin = await authHeader(app, 'a@b.com', 'pw123456', audience)
  assertEquals(
    (await app.request(`/users/${bId}`, {
      headers: { Authorization: aAdmin.Authorization },
    })).status,
    403,
  )

  const platform = `Bearer ${await seedPlatformAdmin(['users:read:any'])}`
  assertEquals(
    (await app.request(`/users/${bId}`, {
      headers: { Authorization: platform },
    })).status,
    200,
  )
})

Deno.test('PATCH /users/:id rejects an empty body, accepts a valid update', async () => {
  const { app, orgRepo } = makeTestApp()
  const id = await registerAndId(app, 'a@b.com')
  const audience = await seedDefaultService(orgRepo, id)
  const { Authorization } = await authHeader(
    app,
    'a@b.com',
    'pw123456',
    audience,
  )

  const empty = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({}),
  })
  assertEquals(empty.status, 400)

  const ok = await app.request(`/users/${id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a2@b.com' }),
  })
  assertEquals(ok.status, 200)
})
