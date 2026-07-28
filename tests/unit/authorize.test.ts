import { assertEquals } from '@std/assert'
import { Hono } from 'hono'
import {
  requirePermission,
  requireSelfOrPermission,
} from '../../src/middleware/authorize.ts'
import type { AppEnv } from '../../src/deps.ts'
import { AppError } from '../../src/lib/errors.ts'

function appWith(
  user: { id: string; permissions: string[]; aud?: string },
) {
  const app = new Hono<AppEnv>()
    .use('*', async (c, next) => {
      c.set('user', {
        id: user.id,
        email: 'x',
        permissions: user.permissions,
        org: 'o1',
        aud: user.aud ?? 'platform',
      })
      await next()
    })
    .get('/list', requirePermission('users:list'), (c) => c.text('ok'))
    .get(
      '/u/:id',
      requireSelfOrPermission('id', 'users:read:any'),
      (c) => c.text('ok'),
    )
  app.onError((e, c) =>
    e instanceof AppError
      ? c.json({ code: e.code }, e.status)
      : c.text('err', 500)
  )
  return app
}

Deno.test('requirePermission allows/denies', async () => {
  assertEquals(
    (await appWith({ id: 'u1', permissions: ['users:list'] }).request('/list'))
      .status,
    200,
  )
  assertEquals(
    (await appWith({ id: 'u1', permissions: [] }).request('/list')).status,
    403,
  )
  // A permission key minted inside a tenant service must not authorize the
  // platform-global route (per-service permission keys can collide).
  assertEquals(
    (await appWith({
      id: 'u1',
      permissions: ['users:list'],
      aud: 'test-service',
    }).request('/list')).status,
    403,
  )
})

Deno.test('requireSelfOrPermission: owner ok, other forbidden, override ok', async () => {
  // Self-service works on any audience (a tenant-service token included).
  assertEquals(
    (await appWith({ id: 'u1', permissions: [], aud: 'test-service' }).request(
      '/u/u1',
    )).status,
    200,
  )
  assertEquals(
    (await appWith({ id: 'u1', permissions: [] }).request('/u/u2')).status,
    403,
  )
  assertEquals(
    (await appWith({ id: 'u1', permissions: ['users:read:any'] }).request(
      '/u/u2',
    ))
      .status,
    200,
  )
  // Same scope, tenant audience: no authority over someone else's record.
  assertEquals(
    (await appWith({
      id: 'u1',
      permissions: ['users:read:any'],
      aud: 'test-service',
    }).request('/u/u2')).status,
    403,
  )
})
