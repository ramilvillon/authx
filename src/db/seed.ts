import { eq } from 'drizzle-orm'
import { loadConfig } from '../config.ts'
import { createDb } from './client.ts'
import { permissions, rolePermissions, roles } from './schema.ts'
import { PERMISSIONS, ROLE_GRANTS } from './rbac-constants.ts'

// Idempotent: find-or-insert each row so re-running is safe.
async function seed() {
  const config = loadConfig(Deno.env.toObject())
  const { db, pool } = createDb(config)

  for (const key of Object.values(PERMISSIONS)) {
    const existing = await db.query.permissions.findFirst({
      where: eq(permissions.key, key),
    })
    if (!existing) {
      await db.insert(permissions).values({ id: crypto.randomUUID(), key })
    }
  }

  const permByKey = new Map(
    (await db.select().from(permissions)).map((p) => [p.key, p.id]),
  )

  for (const [roleName, keys] of Object.entries(ROLE_GRANTS)) {
    let role = await db.query.roles.findFirst({
      where: eq(roles.name, roleName),
    })
    if (!role) {
      const id = crypto.randomUUID()
      await db.insert(roles).values({ id, name: roleName })
      role = { id, name: roleName }
    }
    for (const key of keys) {
      const permissionId = permByKey.get(key)!
      const existing = await db.query.rolePermissions.findFirst({
        where: (rp, { and, eq }) =>
          and(eq(rp.roleId, role.id), eq(rp.permissionId, permissionId)),
      })
      if (!existing) {
        await db.insert(rolePermissions).values({
          roleId: role.id,
          permissionId,
        })
      }
    }
  }

  await pool.end()
  console.log('seed complete')
}

if (import.meta.main) await seed()
