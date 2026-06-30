export type RoleRecord = { id: string; appServiceId: string; name: string }
export type PermissionRecord = { id: string; appServiceId: string; key: string }

export type RbacRepository = {
  createRole(r: RoleRecord): Promise<RoleRecord>
  createPermission(p: PermissionRecord): Promise<PermissionRecord>
  grantPermissionToRole(roleId: string, permissionId: string): Promise<void>
  assignRoleToUser(userId: string, roleId: string): Promise<void>
  findRoleById(id: string): Promise<RoleRecord | null>
  permissionsForUserInService(
    userId: string,
    appServiceId: string,
  ): Promise<string[]>
}

// In-memory test double. Mirror behavior in rbac.repository.drizzle.ts.
export function createInMemoryRbacRepository(): RbacRepository {
  const roles = new Map<string, RoleRecord>()
  const perms = new Map<string, PermissionRecord>()
  const rolePerms = new Set<string>() // `${roleId}:${permissionId}`
  const userRoleIds = new Map<string, Set<string>>() // userId -> roleIds

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
  }
}
