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
}

// In-memory test double. Mirror behavior in rbac.repository.drizzle.ts.
export function createInMemoryRbacRepository(): RbacRepository {
  const roles = new Map<string, RoleRecord>()
  const perms = new Map<string, PermissionRecord>()
  const rolePerms = new Set<string>() // `${roleId}:${permissionId}`
  const userRoleIds = new Map<string, Set<string>>() // userId -> roleIds
  const clientRoleIds = new Map<string, Set<string>>() // clientAppServiceId -> roleIds

  return {
    createRole(r) {
      roles.set(r.id, { ...r })
      return Promise.resolve({ ...r })
    },
    createPermission(p) {
      perms.set(p.id, { ...p })
      return Promise.resolve({ ...p })
    },
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
        if (r.appServiceId === appServiceId && r.name === name) {
          return Promise.resolve({ ...r })
        }
      }
      return Promise.resolve(null)
    },
    findPermissionByKey(appServiceId, key) {
      for (const p of perms.values()) {
        if (p.appServiceId === appServiceId && p.key === key) {
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
  }
}
