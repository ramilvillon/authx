export type UserRecord = {
  id: string
  email: string | null
  username?: string | null
  passwordHash: string | null
  createdAt: Date
  updatedAt: Date
  emailVerified?: boolean
  name?: string | null
  givenName?: string | null
  familyName?: string | null
  picture?: string | null
  deletedAt?: Date | null
}

export type UserWithAccess = UserRecord & {
  roles: string[]
  permissions: string[]
}

export type UserRepository = {
  create(user: UserRecord): Promise<UserRecord>
  findById(id: string): Promise<UserRecord | null>
  findByEmail(email: string): Promise<UserRecord | null>
  // Soft-delete-filtered, exactly like findByEmail: this is a login path.
  findByUsername(username: string): Promise<UserRecord | null>
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
  // Unfiltered on purpose: users.email is UNIQUE, so a soft-deleted row still
  // occupies the address. Registration checks THIS, not findByEmail, so a
  // reused address is reported as taken instead of failing on a duplicate key.
  findAnyByEmail(email: string): Promise<UserRecord | null>
  // Marks the row deleted. false = no such live row.
  softDelete(id: string): Promise<boolean>
  // Ids of rows soft-deleted before `cutoff`, for the purge job.
  findDeletedBefore(cutoff: Date): Promise<string[]>
  // Compare-and-set: sets emailVerified only while the row still holds `email`.
  // false = the address changed since it was checked, so nothing was verified.
  markEmailVerified(id: string, email: string): Promise<boolean>
  // Hard delete. Only the purge path calls this; ordinary deletion is
  // softDelete, and callers must run the satellite cascade first.
  delete(id: string): Promise<boolean>
  list(): Promise<UserRecord[]>
  assignRole(userId: string, roleName: string): Promise<void>
  // user_roles has no foreign key to users, so role grants outlive a deleted
  // account and would be inherited by any future row reusing the id.
  removeAllRoles(userId: string): Promise<number>
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
      const u = byId.get(id)
      return Promise.resolve(u && !u.deletedAt ? { ...u } : null)
    },
    findByEmail(email) {
      for (const u of byId.values()) {
        // `u.email === email` alone would match null-to-null; MySQL's
        // `WHERE email = NULL` never matches. Keep the double as strict as
        // the database or it hides bugs.
        if (u.email !== null && u.email === email && !u.deletedAt) {
          return Promise.resolve({ ...u })
        }
      }
      return Promise.resolve(null)
    },
    findByUsername(username) {
      for (const u of byId.values()) {
        if (u.username && u.username === username && !u.deletedAt) {
          return Promise.resolve({ ...u })
        }
      }
      return Promise.resolve(null)
    },
    findWithAccessById(id) {
      const u = byId.get(id)
      if (!u || u.deletedAt) return Promise.resolve(null)
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
    findAnyByEmail(email) {
      for (const u of byId.values()) {
        if (u.email !== null && u.email === email) {
          return Promise.resolve({ ...u })
        }
      }
      return Promise.resolve(null)
    },
    softDelete(id) {
      const u = byId.get(id)
      if (!u || u.deletedAt) return Promise.resolve(false)
      byId.set(id, { ...u, deletedAt: new Date() })
      return Promise.resolve(true)
    },
    findDeletedBefore(cutoff) {
      const ids: string[] = []
      for (const u of byId.values()) {
        if (u.deletedAt && u.deletedAt.getTime() < cutoff.getTime()) {
          ids.push(u.id)
        }
      }
      return Promise.resolve(ids)
    },
    delete(id) {
      return Promise.resolve(byId.delete(id))
    },
    list() {
      return Promise.resolve(
        [...byId.values()].filter((u) => !u.deletedAt).map((u) => ({ ...u })),
      )
    },
    assignRole(userId, roleName) {
      const set = userRoleNames.get(userId) ?? new Set()
      set.add(roleName)
      userRoleNames.set(userId, set)
      return Promise.resolve()
    },
    removeAllRoles(userId) {
      const n = userRoleNames.get(userId)?.size ?? 0
      userRoleNames.delete(userId)
      return Promise.resolve(n)
    },
  }
}
