import { Hono } from 'hono'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { requireAuth } from '../../middleware/auth.ts'
import { requirePermission } from '../../middleware/authorize.ts'
import {
  addMemberSchema,
  assignRoleSchema,
  createOrgSchema,
  createPermissionSchema,
  createRoleSchema,
  grantPermissionSchema,
  registerServiceSchema,
} from './admin.schema.ts'

// requireAuth is attached per-route (not via .use('*')) so mounting this
// sub-app at '/' doesn't intercept sibling routes like /openapi and /docs.
const admin = new Hono<AppEnv>()
  .post(
    '/orgs',
    requireAuth,
    requirePermission('orgs:write'),
    validator('json', createOrgSchema),
    async (c) =>
      c.json(await c.var.adminService.createOrg(c.req.valid('json')), 201),
  )
  .get('/orgs', requireAuth, requirePermission('orgs:read'), async (c) => {
    return c.json(await c.var.adminService.listOrgs())
  })
  .get('/orgs/:id', requireAuth, requirePermission('orgs:read'), async (c) => {
    return c.json(await c.var.adminService.getOrg(c.req.param('id')))
  })
  .post(
    '/orgs/:id/services',
    requireAuth,
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
    requirePermission('services:read'),
    async (c) => {
      return c.json(await c.var.adminService.listServices(c.req.param('id')))
    },
  )
  .post(
    '/orgs/:id/members',
    requireAuth,
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
