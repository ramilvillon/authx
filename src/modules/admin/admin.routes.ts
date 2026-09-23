import { Hono } from 'hono'
import { createMiddleware } from 'hono/factory'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { requireAuth } from '../../middleware/auth.ts'
import { requirePermission } from '../../middleware/authorize.ts'
import { AppError } from '../../lib/errors.ts'
import {
  addMemberSchema,
  assignClientRoleSchema,
  assignRoleSchema,
  createOrgSchema,
  createPermissionSchema,
  createRoleSchema,
  grantPermissionSchema,
  registerServiceSchema,
  updateServiceSchema,
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
    throw AppError.of('platform_required')
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
  .patch(
    '/services/:id',
    requireAuth,
    requirePlatform,
    requirePermission('services:write'),
    validator('json', updateServiceSchema),
    async (c) =>
      c.json(
        await c.var.adminService.updateService(
          c.req.param('id'),
          c.req.valid('json'),
        ),
      ),
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
  .post(
    '/clients/:clientId/roles',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    validator('json', assignClientRoleSchema),
    async (c) => {
      await c.var.adminService.assignRoleToClient(
        c.req.param('clientId'),
        c.req.valid('json').roleId,
      )
      return c.body(null, 204)
    },
  )
  .get(
    '/services/:id/roles',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:read'),
    async (c) =>
      c.json(
        (await c.var.adminService.listRoles(c.req.param('id'))).map((r) => ({
          id: r.id,
          name: r.name,
          appServiceId: r.appServiceId,
          // Inlined so reviewing a service's RBAC is one request, not one per
          // role. A service holds a handful of roles, so there is nothing to
          // paginate.
          permissions: r.permissions.map((p) => ({ id: p.id, key: p.key })),
        })),
      ),
  )
  .get(
    '/services/:id/permissions',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:read'),
    async (c) =>
      c.json(
        (await c.var.adminService.listPermissions(c.req.param('id'))).map((
          p,
        ) => ({ id: p.id, key: p.key })),
      ),
  )
  .get(
    '/users/:userId/roles',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:read'),
    async (c) =>
      c.json(await c.var.adminService.listUserRoles(c.req.param('userId'))),
  )
  .get(
    '/clients/:clientId/roles',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:read'),
    async (c) =>
      c.json(await c.var.adminService.listClientRoles(c.req.param('clientId'))),
  )
  .delete(
    '/roles/:roleId/permissions/:permissionId',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    async (c) => {
      await c.var.adminService.revokePermission(
        c.req.param('roleId'),
        c.req.param('permissionId'),
      )
      return c.body(null, 204)
    },
  )
  .delete(
    '/users/:userId/roles/:roleId',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    async (c) => {
      await c.var.adminService.removeRole(
        c.req.param('userId'),
        c.req.param('roleId'),
      )
      return c.body(null, 204)
    },
  )
  .delete(
    '/clients/:clientId/roles/:roleId',
    requireAuth,
    requirePlatform,
    requirePermission('rbac:write'),
    async (c) => {
      await c.var.adminService.removeClientRole(
        c.req.param('clientId'),
        c.req.param('roleId'),
      )
      return c.body(null, 204)
    },
  )

export default admin
