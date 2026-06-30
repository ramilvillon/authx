import { assertEquals } from '@std/assert'
import { authHeader, makeTestApp } from '../helpers.ts'

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
  const { app } = makeTestApp()
  await registerAndId(app, 'a@b.com')
  const { Authorization } = await authHeader(app, 'a@b.com', 'pw123456')
  assertEquals(
    (await app.request('/users', { headers: { Authorization } })).status,
    403,
  )
})

Deno.test('admin can list users', async () => {
  const { app, userRepo } = makeTestApp()
  const id = await registerAndId(app, 'admin@b.com')
  await userRepo.assignRole(id, 'admin')
  const { Authorization } = await authHeader(app, 'admin@b.com', 'pw123456')
  assertEquals(
    (await app.request('/users', { headers: { Authorization } })).status,
    200,
  )
})

Deno.test('user can read self but not others; admin can read others', async () => {
  const { app, userRepo } = makeTestApp()
  const aId = await registerAndId(app, 'a@b.com')
  const bId = await registerAndId(app, 'b@b.com')
  const aAuth = await authHeader(app, 'a@b.com', 'pw123456')
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

  await userRepo.assignRole(aId, 'admin')
  const aAdmin = await authHeader(app, 'a@b.com', 'pw123456')
  assertEquals(
    (await app.request(`/users/${bId}`, {
      headers: { Authorization: aAdmin.Authorization },
    })).status,
    200,
  )
})

Deno.test('PATCH /users/:id rejects an empty body, accepts a valid update', async () => {
  const { app } = makeTestApp()
  const id = await registerAndId(app, 'a@b.com')
  const { Authorization } = await authHeader(app, 'a@b.com', 'pw123456')

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
