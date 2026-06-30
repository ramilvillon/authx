import { eq } from 'drizzle-orm'
import { loadConfig } from '../config.ts'
import { createDb } from './client.ts'
import {
  appServices,
  memberships,
  organizations,
  permissions,
  rolePermissions,
  roles,
  userRoles,
  users,
} from './schema.ts'
import {
  PLATFORM_AUDIENCE,
  PLATFORM_CLIENT_ID,
  PLATFORM_ORG_SLUG,
  PLATFORM_PERMISSIONS,
  ROLE_ADMIN,
} from './rbac-constants.ts'
import { hashPassword } from '../lib/password.ts'

// Idempotent: find-or-insert each row so re-running is safe.
async function seed() {
  const config = loadConfig(Deno.env.toObject())
  const { db, pool } = createDb(config)
  const now = new Date()

  // 1. platform org
  let org = await db.query.organizations.findFirst({
    where: eq(organizations.slug, PLATFORM_ORG_SLUG),
  })
  if (!org) {
    const id = crypto.randomUUID()
    await db.insert(organizations).values({
      id,
      slug: PLATFORM_ORG_SLUG,
      name: 'Platform',
      createdAt: now,
    })
    org = { id, slug: PLATFORM_ORG_SLUG, name: 'Platform', createdAt: now }
  }

  // 2. platform app service (audience that gates the management API)
  let service = await db.query.appServices.findFirst({
    where: eq(appServices.audience, PLATFORM_AUDIENCE),
  })
  if (!service) {
    const id = crypto.randomUUID()
    await db.insert(appServices).values({
      id,
      orgId: org.id,
      clientId: PLATFORM_CLIENT_ID,
      name: 'Platform',
      slug: PLATFORM_ORG_SLUG,
      audience: PLATFORM_AUDIENCE,
      type: 'confidential',
      createdAt: now,
    })
    service = (await db.query.appServices.findFirst({
      where: eq(appServices.audience, PLATFORM_AUDIENCE),
    }))!
  }

  // 3. permissions for the platform service
  for (const key of PLATFORM_PERMISSIONS) {
    const existing = await db.query.permissions.findFirst({
      where: (p, { and, eq }) =>
        and(eq(p.appServiceId, service.id), eq(p.key, key)),
    })
    if (!existing) {
      await db.insert(permissions).values({
        id: crypto.randomUUID(),
        appServiceId: service.id,
        key,
      })
    }
  }
  const permByKey = new Map(
    (await db.select().from(permissions).where(
      eq(permissions.appServiceId, service.id),
    )).map((p) => [p.key, p.id]),
  )

  // 4. admin role for the platform service; grant every platform permission
  let role = await db.query.roles.findFirst({
    where: (r, { and, eq }) =>
      and(eq(r.appServiceId, service.id), eq(r.name, ROLE_ADMIN)),
  })
  if (!role) {
    const id = crypto.randomUUID()
    await db.insert(roles).values({
      id,
      appServiceId: service.id,
      name: ROLE_ADMIN,
    })
    role = { id, appServiceId: service.id, name: ROLE_ADMIN }
  }
  for (const key of PLATFORM_PERMISSIONS) {
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

  // 5. bootstrap admin user from env (optional)
  const adminEmail = Deno.env.get('BOOTSTRAP_ADMIN_EMAIL')
  const adminPassword = Deno.env.get('BOOTSTRAP_ADMIN_PASSWORD')
  if (adminEmail && adminPassword) {
    let user = await db.query.users.findFirst({
      where: eq(users.email, adminEmail),
    })
    if (!user) {
      const id = crypto.randomUUID()
      await db.insert(users).values({
        id,
        email: adminEmail,
        passwordHash: await hashPassword(adminPassword),
        createdAt: now,
        updatedAt: now,
      })
      user = (await db.query.users.findFirst({
        where: eq(users.email, adminEmail),
      }))!
    }

    const member = await db.query.memberships.findFirst({
      where: (m, { and, eq }) =>
        and(eq(m.userId, user.id), eq(m.orgId, org.id)),
    })
    if (!member) {
      await db.insert(memberships).values({
        id: crypto.randomUUID(),
        userId: user.id,
        orgId: org.id,
        createdAt: now,
      })
    }

    const hasRole = await db.query.userRoles.findFirst({
      where: (ur, { and, eq }) =>
        and(eq(ur.userId, user.id), eq(ur.roleId, role.id)),
    })
    if (!hasRole) {
      await db.insert(userRoles).values({ userId: user.id, roleId: role.id })
    }
    console.log(`bootstrap admin: ${adminEmail}`)
  }

  await pool.end()
  console.log(`seed complete (platform client_id=${PLATFORM_CLIENT_ID})`)
}

if (import.meta.main) await seed()
