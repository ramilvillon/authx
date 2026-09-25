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
import { hashPassword, verifyPassword } from '../lib/password.ts'
import { assertAcceptablePassword } from '../lib/password-policy.ts'

// The password `.env.example` used to ship. A `.env` copied from that template
// would seed a platform admin whose password is public, so refuse it.
const SHIPPED_PLACEHOLDER_PASSWORD = 'change-me-please'

// Returns the bootstrap admin credentials, or null when either half is unset
// (step 5 below is skipped, exactly as before). Throws for a password the
// policy refuses, and names the shipped placeholder specifically.
export function bootstrapAdminFromEnv(
  email: string | undefined,
  password: string | undefined,
): { email: string; password: string } | null {
  if (!email || !password) return null
  if (password === SHIPPED_PLACEHOLDER_PASSWORD) {
    throw new Error(
      'BOOTSTRAP_ADMIN_PASSWORD is the placeholder from the old .env.example. ' +
        'Set a real password, or clear BOOTSTRAP_ADMIN_EMAIL/BOOTSTRAP_ADMIN_PASSWORD to skip the bootstrap admin.',
    )
  }
  // The same policy a person choosing a password anywhere else gets. This
  // account holds every platform permission, so it is the last one to exempt.
  try {
    assertAcceptablePassword(password)
  } catch (e) {
    throw new Error(
      `BOOTSTRAP_ADMIN_PASSWORD is not acceptable: ${(e as Error).message}`,
    )
  }
  return { email, password }
}

// What step 5 does about an account that may already hold BOOTSTRAP_ADMIN_EMAIL.
// Adopting ANY such row used to make whoever registered the address first the
// platform admin, with their own password. An existing account is adopted only
// when it is already platform admin (the seed's own admin on a re-run, even
// after its password was changed through the API) or when the operator knows
// its password (they registered first, then pointed the seed at themselves).
export function bootstrapAdminAction(
  existing: { hasAdminRole: boolean; passwordMatches: boolean } | null,
): 'create' | 'adopt' | 'refuse' {
  if (!existing) return 'create'
  if (existing.hasAdminRole || existing.passwordMatches) return 'adopt'
  return 'refuse'
}

// Idempotent: find-or-insert each row so re-running is safe.
async function seed() {
  // Checked before connecting so a stale template never reaches step 5.
  const admin = bootstrapAdminFromEnv(
    Deno.env.get('BOOTSTRAP_ADMIN_EMAIL'),
    Deno.env.get('BOOTSTRAP_ADMIN_PASSWORD'),
  )
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
  if (admin) {
    const { email: adminEmail, password: adminPassword } = admin
    const found = await db.query.users.findFirst({
      where: eq(users.email, adminEmail),
    })
    const action = bootstrapAdminAction(
      found
        ? {
          hasAdminRole: !!(await db.query.userRoles.findFirst({
            where: (ur, { and, eq }) =>
              and(eq(ur.userId, found.id), eq(ur.roleId, role.id)),
          })),
          passwordMatches: found.passwordHash !== null &&
            await verifyPassword(adminPassword, found.passwordHash),
        }
        : null,
    )
    if (action === 'refuse') {
      await pool.end()
      throw new Error(
        `An account with BOOTSTRAP_ADMIN_EMAIL (${adminEmail}) already exists, ` +
          'is not a platform admin, and BOOTSTRAP_ADMIN_PASSWORD does not match ' +
          'its password -- so the seed did not create it and cannot tell it ' +
          'belongs to you. Refusing to make it platform admin. If it is yours, ' +
          'set BOOTSTRAP_ADMIN_PASSWORD to its password; otherwise choose a ' +
          'different BOOTSTRAP_ADMIN_EMAIL.',
      )
    }
    let user = found
    // 'create' is exactly the no-account case; keyed on `user` so it narrows.
    if (!user) {
      const id = crypto.randomUUID()
      await db.insert(users).values({
        id,
        email: adminEmail,
        passwordHash: await hashPassword(adminPassword),
        // The operator named this address in the deploy config, which is the
        // proof; left unverified, REQUIRE_EMAIL_VERIFICATION would lock the
        // platform's own admin out on first boot. Only a row created HERE: an
        // adopted row keeps the state it had, because knowing its password
        // proves control of the account, not of the inbox.
        emailVerified: true,
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
