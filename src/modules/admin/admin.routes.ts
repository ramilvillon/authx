import { Hono } from 'hono'
import { createMiddleware } from 'hono/factory'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { requireAuth } from '../../middleware/auth.ts'
import { requirePermission } from '../../middleware/authorize.ts'
import { AppError } from '../../lib/errors.ts'
import {
  addMemberSchema,
  assignRoleSchema,
  createOrgSchema,
  createPermissionSchema,
  createRoleSchema,
  grantPermissionSchema,
  registerServiceSchema,
} from './admin.schema.ts'

// The management API is reserved for tokens minted for the platform service.
// Permission keys are defined per-service, so checking only the permission
// string would let a service-scoped token whose RBAC defines a colliding key
// (e.g. 'orgs:write') escalate to platform admin. Bind authz to the platform
// audience too. We key on `aud` (the unique, reserved platform service) rather
// than `org`, which is a per-tenant UUID at runtime.
const PLATFORM_AUDIENCE = 'platform'
const requirePlatform = createMiddleware<AppEnv>(async (c, next) => {
  if (c.var.user.aud !== PLATFORM_AUDIENCE) {
    throw AppError.forbidden('platform token required')
  }
  await next()
})

// requireAuth is attached per-route (not via .use('*')) so mounting this
// sub-app at '/' doesn't intercept sibling routes like /openapi and /docs.
const admin = new Hono<AppEnv>()
  .post(
    '/orgs',
    requireAuth,
    requirePlatform,
    requirePermission('orgs:write'),
    validator('json', createOrgSchema),
    async (c) =>
      c.json(await c.var.adminService.createOrg(c.req.valid('json')), 201),
  )
  .get(
    '/orgs',
    requireAuth,
    requirePlatform,
    requirePermission('orgs:read'),
    async (c) => {
      return c.json(await c.var.adminService.listOrgs())
    },
  )
  .get(
    '/orgs/:id',
    requireAuth,
    requirePlatform,
    requirePermission('orgs:read'),
    async (c) => {
      return c.json(await c.var.adminService.getOrg(c.req.param('id')))
    },
  )
  .post(
    '/orgs/:id/services',
    requireAuth,
    requirePlatform,
    requirePermission('services:write'),
    validator('json', registerServiceSchema),
    async (c) =>
      c.json(
        await c.var.adminService.registerService(
          c.req.param('id'),
          c.req.valid('json'),
        ),
        201,
      ),
  )
  .get(
    '/orgs/:id/services',
    requireAuth,
    requirePlatform,
    requirePermission('services:read'),
    async (c) => {
      return c.json(await c.var.adminService.listServices(c.req.param('id')))
    },
  )
  .post(
    '/orgs/:id/members',
    requireAuth,
    requirePlatform,
    requirePermission('members:write'),
    validator('json', addMemberSchema),
    async (c) => {
      await c.var.adminService.addMember(
        c.req.param('id'),
        c.req.valid('json').userId,
      )
      return c.body(null, 204)
    },
  )
  .delete(
    '/orgs/:id/members/:userId',
    requireAuth,
    requirePlatform,
    requirePermission('members:write'),
    async (c) => {
      await c.var.adminService.removeMember(
        c.req.param('id'),
        c.req.param('userId'),
      )
      return c.body(null, 204)
    },
  )
  .post(
    '/services/:id/roles',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    validator('json', createRoleSchema),
    async (c) =>
      c.json(
        await c.var.adminService.createRole(
          c.req.param('id'),
          c.req.valid('json').name,
        ),
        201,
      ),
  )
  .post(
    '/services/:id/permissions',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    validator('json', createPermissionSchema),
    async (c) =>
      c.json(
        await c.var.adminService.createPermission(
          c.req.param('id'),
          c.req.valid('json').key,
        ),
        201,
      ),
  )
  .post(
    '/roles/:id/permissions',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    validator('json', grantPermissionSchema),
    async (c) => {
      await c.var.adminService.grantPermission(
        c.req.param('id'),
        c.req.valid('json').permissionId,
      )
      return c.body(null, 204)
    },
  )
  .post(
    '/users/:userId/roles',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    validator('json', assignRoleSchema),
    async (c) => {
      await c.var.adminService.assignRole(
        c.req.param('userId'),
        c.req.valid('json').roleId,
      )
      return c.body(null, 204)
    },
  )

export default admin
