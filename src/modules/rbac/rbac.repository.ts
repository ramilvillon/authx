import { ciEquals, duplicateKey } from '../../lib/inmemory.ts'

export type RoleRecord = { id: string; appServiceId: string; name: string }
export type PermissionRecord = { id: string; appServiceId: string; key: string }

export type RbacRepository = {
  createRole(r: RoleRecord): Promise<RoleRecord>
  createPermission(p: PermissionRecord): Promise<PermissionRecord>
  grantPermissionToRole(roleId: string, permissionId: string): Promise<void>
  assignRoleToUser(userId: string, roleId: string): Promise<void>
  assignRoleToClient(clientAppServiceId: string, roleId: string): Promise<void>
  findRoleById(id: string): Promise<RoleRecord | null>
  // Both constraints are (app_service_id, name/key), not the name alone --
  // per-service RBAC depends on two services being able to use the same name.
  findRoleByName(appServiceId: string, name: string): Promise<RoleRecord | null>
  findPermissionByKey(
    appServiceId: string,
    key: string,
  ): Promise<PermissionRecord | null>
  permissionsForUserInService(
    userId: string,
    appServiceId: string,
  ): Promise<string[]>
  permissionsForClientInService(
    clientAppServiceId: string,
    appServiceId: string,
  ): Promise<string[]>
  // Revokes are DELETEs on the join tables: a row that is not there is already
  // in the wanted state, so they resolve either way rather than reporting a
  // miss. The routes are 204 for the same reason.
  revokePermissionFromRole(roleId: string, permissionId: string): Promise<void>
  removeRoleFromUser(userId: string, roleId: string): Promise<void>
  removeRoleFromClient(
    clientAppServiceId: string,
    roleId: string,
  ): Promise<void>
  listRolesForService(appServiceId: string): Promise<RoleWithPermissions[]>
  listPermissionsForService(appServiceId: string): Promise<PermissionRecord[]>
  rolesForUser(userId: string): Promise<RoleRecord[]>
  rolesForClient(clientAppServiceId: string): Promise<RoleRecord[]>
}

export type RoleWithPermissions = RoleRecord & {
  permissions: PermissionRecord[]
}

// In-memory test double. Mirror behavior in rbac.repository.drizzle.ts.
export function createInMemoryRbacRepository(): RbacRepository {
  const roles = new Map<string, RoleRecord>()
  const perms = new Map<string, PermissionRecord>()
  const rolePerms = new Set<string>() // `${roleId}:${permissionId}`
  const userRoleIds = new Map<string, Set<string>>() // userId -> roleIds
  const clientRoleIds = new Map<string, Set<string>>() // clientAppServiceId -> roleIds

  return {
    async createRole(r) {
      for (const existing of roles.values()) {
        if (existing.id === r.id) throw duplicateKey('roles', 'PRIMARY', r.id)
        if (
          existing.appServiceId === r.appServiceId &&
          ciEquals(existing.name, r.name)
        ) {
          throw duplicateKey('roles', 'app_service_id_name', r.name)
        }
      }
      roles.set(r.id, { ...r })
      return await Promise.resolve({ ...r })
    },
    async createPermission(p) {
      for (const existing of perms.values()) {
        if (existing.id === p.id) {
          throw duplicateKey('permissions', 'PRIMARY', p.id)
        }
        if (
          existing.appServiceId === p.appServiceId &&
          ciEquals(existing.key, p.key)
        ) {
          throw duplicateKey('permissions', 'app_service_id_key', p.key)
        }
      }
      perms.set(p.id, { ...p })
      return await Promise.resolve({ ...p })
    },
    // The three join tables below are Sets keyed by their composite PRIMARY
    // KEY, so a repeat is a no-op. That is deliberate and matches the drizzle
    // side, which inserts with onDuplicateKeyUpdate -- do not make these throw.
    grantPermissionToRole(roleId, permissionId) {
      rolePerms.add(`${roleId}:${permissionId}`)
      return Promise.resolve()
    },
    assignRoleToUser(userId, roleId) {
      const set = userRoleIds.get(userId) ?? new Set()
      set.add(roleId)
      userRoleIds.set(userId, set)
      return Promise.resolve()
    },
    findRoleById(id) {
      return Promise.resolve(roles.has(id) ? { ...roles.get(id)! } : null)
    },
    findRoleByName(appServiceId, name) {
      for (const r of roles.values()) {
        if (r.appServiceId === appServiceId && ciEquals(r.name, name)) {
          return Promise.resolve({ ...r })
        }
      }
      return Promise.resolve(null)
    },
    findPermissionByKey(appServiceId, key) {
      for (const p of perms.values()) {
        if (p.appServiceId === appServiceId && ciEquals(p.key, key)) {
          return Promise.resolve({ ...p })
        }
      }
      return Promise.resolve(null)
    },
    permissionsForUserInService(userId, appServiceId) {
      const out = new Set<string>()
      for (const roleId of userRoleIds.get(userId) ?? []) {
        const role = roles.get(roleId)
        if (!role || role.appServiceId !== appServiceId) continue
        for (const p of perms.values()) {
          if (rolePerms.has(`${roleId}:${p.id}`)) out.add(p.key)
        }
      }
      return Promise.resolve([...out])
    },
    assignRoleToClient(clientAppServiceId, roleId) {
      const set = clientRoleIds.get(clientAppServiceId) ?? new Set()
      set.add(roleId)
      clientRoleIds.set(clientAppServiceId, set)
      return Promise.resolve()
    },
    permissionsForClientInService(clientAppServiceId, appServiceId) {
      const out = new Set<string>()
      for (const roleId of clientRoleIds.get(clientAppServiceId) ?? []) {
        const role = roles.get(roleId)
        if (!role || role.appServiceId !== appServiceId) continue
        for (const p of perms.values()) {
          if (rolePerms.has(`${roleId}:${p.id}`)) out.add(p.key)
        }
      }
      return Promise.resolve([...out])
    },
    revokePermissionFromRole(roleId, permissionId) {
      rolePerms.delete(`${roleId}:${permissionId}`)
      return Promise.resolve()
    },
    removeRoleFromUser(userId, roleId) {
      userRoleIds.get(userId)?.delete(roleId)
      return Promise.resolve()
    },
    removeRoleFromClient(clientAppServiceId, roleId) {
      clientRoleIds.get(clientAppServiceId)?.delete(roleId)
      return Promise.resolve()
    },
    listRolesForService(appServiceId) {
      const out = []
      for (const role of roles.values()) {
        if (role.appServiceId !== appServiceId) continue
        out.push({
          ...role,
          permissions: [...perms.values()]
            .filter((p) => rolePerms.has(`${role.id}:${p.id}`))
            .map((p) => ({ ...p })),
        })
      }
      return Promise.resolve(out)
    },
    listPermissionsForService(appServiceId) {
      return Promise.resolve(
        [...perms.values()]
          .filter((p) => p.appServiceId === appServiceId)
          .map((p) => ({ ...p })),
      )
    },
    rolesForUser(userId) {
      return Promise.resolve(rolesByIds(userRoleIds.get(userId)))
    },
    rolesForClient(clientAppServiceId) {
      return Promise.resolve(rolesByIds(clientRoleIds.get(clientAppServiceId)))
    },
  }

  function rolesByIds(ids: Set<string> | undefined): RoleRecord[] {
    return [...ids ?? []]
      .map((id) => roles.get(id))
      .filter((r): r is RoleRecord => !!r)
      .map((r) => ({ ...r }))
  }
}
