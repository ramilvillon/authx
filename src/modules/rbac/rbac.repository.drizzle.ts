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
    async findRoleByName(appServiceId, name) {
      const row = await db.query.roles.findFirst({
        where: and(eq(roles.appServiceId, appServiceId), eq(roles.name, name)),
      })
      return row ?? null
    },
    async findPermissionByKey(appServiceId, key) {
      const row = await db.query.permissions.findFirst({
        where: and(
          eq(permissions.appServiceId, appServiceId),
          eq(permissions.key, key),
        ),
      })
      return row ?? null
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
    async revokePermissionFromRole(roleId, permissionId) {
      await db.delete(rolePermissions).where(
        and(
          eq(rolePermissions.roleId, roleId),
          eq(rolePermissions.permissionId, permissionId),
        ),
      )
    },
    async removeRoleFromUser(userId, roleId) {
      await db.delete(userRoles).where(
        and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)),
      )
    },
    async removeRoleFromClient(clientAppServiceId, roleId) {
      await db.delete(clientRoles).where(
        and(
          eq(clientRoles.clientAppServiceId, clientAppServiceId),
          eq(clientRoles.roleId, roleId),
        ),
      )
    },
    async listRolesForService(appServiceId) {
      const roleRows = await db.select().from(roles).where(
        eq(roles.appServiceId, appServiceId),
      )
      if (!roleRows.length) return []
      // One join for every role's grants, then group in memory: a service has
      // a handful of roles, so this is two queries whatever the count.
      const grants = await db.select({
        roleId: rolePermissions.roleId,
        id: permissions.id,
        appServiceId: permissions.appServiceId,
        key: permissions.key,
      })
        .from(rolePermissions)
        .innerJoin(
          permissions,
          eq(rolePermissions.permissionId, permissions.id),
        )
        .where(inArray(rolePermissions.roleId, roleRows.map((r) => r.id)))
      return roleRows.map((role) => ({
        ...role,
        permissions: grants
          .filter((g) => g.roleId === role.id)
          .map(({ id, appServiceId, key }) => ({ id, appServiceId, key })),
      }))
    },
    listPermissionsForService(appServiceId) {
      return db.select().from(permissions).where(
        eq(permissions.appServiceId, appServiceId),
      )
    },
    rolesForUser(userId) {
      return db.select({
        id: roles.id,
        appServiceId: roles.appServiceId,
        name: roles.name,
      })
        .from(userRoles)
        .innerJoin(roles, eq(userRoles.roleId, roles.id))
        .where(eq(userRoles.userId, userId))
    },
    rolesForClient(clientAppServiceId) {
      return db.select({
        id: roles.id,
        appServiceId: roles.appServiceId,
        name: roles.name,
      })
        .from(clientRoles)
        .innerJoin(roles, eq(clientRoles.roleId, roles.id))
        .where(eq(clientRoles.clientAppServiceId, clientAppServiceId))
    },
  }
}
