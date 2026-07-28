export type UserRecord = {
  id: string
  email: string
  passwordHash: string | null
  createdAt: Date
  updatedAt: Date
  emailVerified?: boolean
  name?: string | null
  givenName?: string | null
  familyName?: string | null
  picture?: string | null
}

export type UserWithAccess = UserRecord & {
  roles: string[]
  permissions: string[]
}

export type UserRepository = {
  create(user: UserRecord): Promise<UserRecord>
  findById(id: string): Promise<UserRecord | null>
  findByEmail(email: string): Promise<UserRecord | null>
  findWithAccessById(id: string): Promise<UserWithAccess | null>
  update(
    id: string,
    patch: Partial<
      Pick<
        UserRecord,
        | 'email'
        | 'passwordHash'
        | 'emailVerified'
        | 'name'
        | 'givenName'
        | 'familyName'
        | 'picture'
      >
    >,
  ): Promise<UserRecord | null>
  // Compare-and-set: sets emailVerified only while the row still holds `email`.
  // false = the address changed since it was checked, so nothing was verified.
  markEmailVerified(id: string, email: string): Promise<boolean>
  delete(id: string): Promise<boolean>
  list(): Promise<UserRecord[]>
  assignRole(userId: string, roleName: string): Promise<void>
}

// In-memory test double for UserRepository: lets the unit/integration suite
// run without MySQL. Mirror any behavior change in users.repository.drizzle.ts.
// roleGrants maps roleName -> permission keys (mirrors seeded RBAC data).
export function createInMemoryUserRepository(
  roleGrants: Record<string, string[]> = { user: [] },
): UserRepository {
  const byId = new Map<string, UserRecord>()
  const userRoleNames = new Map<string, Set<string>>()

  return {
    create(user) {
      byId.set(user.id, { ...user })
      return Promise.resolve({ ...user })
    },
    findById(id) {
      return Promise.resolve(byId.has(id) ? { ...byId.get(id)! } : null)
    },
    findByEmail(email) {
      for (const u of byId.values()) {
        if (u.email === email) return Promise.resolve({ ...u })
      }
      return Promise.resolve(null)
    },
    findWithAccessById(id) {
      const u = byId.get(id)
      if (!u) return Promise.resolve(null)
      const roleNames = [...(userRoleNames.get(id) ?? [])]
      const perms = new Set<string>()
      for (const r of roleNames) {
        for (const p of roleGrants[r] ?? []) perms.add(p)
      }
      return Promise.resolve({
        ...u,
        roles: roleNames,
        permissions: [...perms],
      })
    },
    update(id, patch) {
      const u = byId.get(id)
      if (!u) return Promise.resolve(null)
      const next = { ...u, ...patch, updatedAt: new Date() }
      byId.set(id, next)
      return Promise.resolve({ ...next })
    },
    markEmailVerified(id, email) {
      const u = byId.get(id)
      if (!u || u.email !== email) return Promise.resolve(false)
      byId.set(id, { ...u, emailVerified: true, updatedAt: new Date() })
      return Promise.resolve(true)
    },
    delete(id) {
      return Promise.resolve(byId.delete(id))
    },
    list() {
      return Promise.resolve([...byId.values()].map((u) => ({ ...u })))
    },
    assignRole(userId, roleName) {
      const set = userRoleNames.get(userId) ?? new Set()
      set.add(roleName)
      userRoleNames.set(userId, set)
      return Promise.resolve()
    },
  }
}
