import { and, eq, inArray, isNull, lt } from 'drizzle-orm'
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
  // Soft-deleted rows are invisible to every ordinary lookup. This is THE
  // chokepoint: requireAuth, passwordGrant, refreshGrant and session
  // resolution all reach a user through findById/findByEmail, so none of them
  // needs its own check and none of them can forget one.
  const live = isNull(users.deletedAt)

  async function findById(id: string): Promise<UserRecord | null> {
    const row = await db.query.users.findFirst({
      where: and(eq(users.id, id), live),
    })
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
        where: and(eq(users.email, email), live),
      })
      return row ?? null
    },
    async findByUsername(username) {
      const row = await db.query.users.findFirst({
        where: and(eq(users.username, username), live),
      })
      return row ?? null
    },
    async findAnyByEmail(email) {
      // Deliberately unfiltered: users.email is UNIQUE, so a soft-deleted row
      // still occupies the address.
      const row = await db.query.users.findFirst({
        where: eq(users.email, email),
      })
      return row ?? null
    },
    async softDelete(id) {
      const [res] = await db.update(users)
        .set({ deletedAt: new Date(), updatedAt: new Date() })
        .where(and(eq(users.id, id), live))
      return (res as { affectedRows: number }).affectedRows === 1
    },
    async findDeletedBefore(cutoff) {
      const rows = await db.select({ id: users.id }).from(users).where(
        and(lt(users.deletedAt, cutoff)),
      )
      return rows.map((r) => r.id)
    },
    async findWithAccessById(id): Promise<UserWithAccess | null> {
      const user = await db.query.users.findFirst({
        where: and(eq(users.id, id), live),
      })
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
    // Erasure. Only userService.purgeDeletedBefore calls this, after the grace
    // period and after running the satellite cascade; the schema has no foreign
    // keys to do that for us. Ordinary deletion is softDelete.
    async delete(id) {
      const [res] = await db.delete(users).where(eq(users.id, id))
      return (res as { affectedRows: number }).affectedRows > 0
    },
    async list() {
      return await db.select().from(users).where(live)
    },
    async assignRole(userId, roleName) {
      const role = await db.query.roles.findFirst({
        where: eq(roles.name, roleName),
      })
      if (!role) throw new Error(`role ${roleName} not seeded`)
      await db.insert(userRoles).values({ userId, roleId: role.id })
        .onDuplicateKeyUpdate({ set: { userId } })
    },
    async removeAllRoles(userId) {
      const [res] = await db.delete(userRoles).where(
        eq(userRoles.userId, userId),
      )
      return (res as { affectedRows: number }).affectedRows
    },
  }
}
