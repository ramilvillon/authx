import { and, eq, inArray } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import {
  permissions,
  rolePermissions,
  roles,
  userRoles,
  users,
} from '../../db/schema.ts'
import type {
  UserRecord,
  UserRepository,
  UserWithAccess,
} from './users.repository.ts'

export function createDrizzleUserRepository(db: Database): UserRepository {
  async function findById(id: string): Promise<UserRecord | null> {
    const row = await db.query.users.findFirst({ where: eq(users.id, id) })
    return row ?? null
  }

  return {
    async create(user) {
      await db.insert(users).values(user)
      return user
    },
    findById,
    async findByEmail(email) {
      const row = await db.query.users.findFirst({
        where: eq(users.email, email),
      })
      return row ?? null
    },
    async findWithAccessById(id): Promise<UserWithAccess | null> {
      const user = await db.query.users.findFirst({ where: eq(users.id, id) })
      if (!user) return null
      const roleRows = await db.select({ id: roles.id, name: roles.name })
        .from(userRoles)
        .innerJoin(roles, eq(userRoles.roleId, roles.id))
        .where(eq(userRoles.userId, id))
      const roleIds = roleRows.map((r) => r.id)
      const permRows = roleIds.length
        ? await db.select({ key: permissions.key })
          .from(rolePermissions)
          .innerJoin(
            permissions,
            eq(rolePermissions.permissionId, permissions.id),
          )
          .where(inArray(rolePermissions.roleId, roleIds))
        : []
      return {
        ...user,
        roles: roleRows.map((r) => r.name),
        permissions: [...new Set(permRows.map((p) => p.key))],
      }
    },
    async update(id, patch) {
      await db.update(users).set({ ...patch, updatedAt: new Date() }).where(
        eq(users.id, id),
      )
      return findById(id)
    },
    async markEmailVerified(id, email) {
      const [res] = await db.update(users)
        .set({ emailVerified: true, updatedAt: new Date() })
        .where(and(eq(users.id, id), eq(users.email, email)))
      // affectedRows counts rows MATCHED (mysql2 connects with FOUND_ROWS), so
      // re-verifying an already-verified row still reports 1.
      return (res as { affectedRows: number }).affectedRows === 1
    },
    async delete(id) {
      const [res] = await db.delete(users).where(eq(users.id, id))
      return (res as { affectedRows: number }).affectedRows > 0
    },
    async list() {
      return await db.select().from(users)
    },
    async assignRole(userId, roleName) {
      const role = await db.query.roles.findFirst({
        where: eq(roles.name, roleName),
      })
      if (!role) throw new Error(`role ${roleName} not seeded`)
      await db.insert(userRoles).values({ userId, roleId: role.id })
        .onDuplicateKeyUpdate({ set: { userId } })
    },
  }
}
