import { and, eq, inArray } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import {
  clientRoles,
  permissions,
  rolePermissions,
  roles,
  userRoles,
} from '../../db/schema.ts'
import type { RbacRepository } from './rbac.repository.ts'

export function createDrizzleRbacRepository(db: Database): RbacRepository {
  return {
    async createRole(r) {
      await db.insert(roles).values(r)
      return r
    },
    async createPermission(p) {
      await db.insert(permissions).values(p)
      return p
    },
    async grantPermissionToRole(roleId, permissionId) {
      await db.insert(rolePermissions).values({ roleId, permissionId })
        .onDuplicateKeyUpdate({ set: { roleId } })
    },
    async assignRoleToUser(userId, roleId) {
      await db.insert(userRoles).values({ userId, roleId })
        .onDuplicateKeyUpdate({ set: { userId } })
    },
    async findRoleById(id) {
      const row = await db.query.roles.findFirst({ where: eq(roles.id, id) })
      return row ?? null
    },
    async permissionsForUserInService(userId, appServiceId) {
      const roleRows = await db.select({ id: roles.id })
        .from(userRoles)
        .innerJoin(roles, eq(userRoles.roleId, roles.id))
        .where(
          and(
            eq(userRoles.userId, userId),
            eq(roles.appServiceId, appServiceId),
          ),
        )
      const roleIds = roleRows.map((r) => r.id)
      if (!roleIds.length) return []
      const permRows = await db.select({ key: permissions.key })
        .from(rolePermissions)
        .innerJoin(
          permissions,
          eq(rolePermissions.permissionId, permissions.id),
        )
        .where(inArray(rolePermissions.roleId, roleIds))
      return [...new Set(permRows.map((p) => p.key))]
    },
    async assignRoleToClient(clientAppServiceId, roleId) {
      await db.insert(clientRoles).values({ clientAppServiceId, roleId })
        .onDuplicateKeyUpdate({ set: { clientAppServiceId } })
    },
    async permissionsForClientInService(clientAppServiceId, appServiceId) {
      const roleRows = await db.select({ id: roles.id })
        .from(clientRoles)
        .innerJoin(roles, eq(clientRoles.roleId, roles.id))
        .where(
          and(
            eq(clientRoles.clientAppServiceId, clientAppServiceId),
            eq(roles.appServiceId, appServiceId),
          ),
        )
      const roleIds = roleRows.map((r) => r.id)
      if (!roleIds.length) return []
      const permRows = await db.select({ key: permissions.key })
        .from(rolePermissions)
        .innerJoin(
          permissions,
          eq(rolePermissions.permissionId, permissions.id),
        )
        .where(inArray(rolePermissions.roleId, roleIds))
      return [...new Set(permRows.map((p) => p.key))]
    },
  }
}
