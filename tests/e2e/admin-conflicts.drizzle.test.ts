import { assertEquals, assertRejects } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleOrgRepository } from '../../src/modules/orgs/orgs.repository.drizzle.ts'
import { createDrizzleRbacRepository } from '../../src/modules/rbac/rbac.repository.drizzle.ts'
import { createAdminService } from '../../src/modules/admin/admin.service.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

// This is the test the in-memory doubles structurally cannot provide. They are
// Maps and enforce no UNIQUE constraint, so a missing guard looks identical to
// a present one there. Only MySQL can tell the difference: without the guard
// these raise a raw driver error that surfaces as a 500 `internal`.
Deno.test({
  name:
    'admin duplicate creates are conflicts against real MySQL (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const orgRepo = createDrizzleOrgRepository(db)
    const rbacRepo = createDrizzleRbacRepository(db)
    const svc = createAdminService({ orgRepo, rbacRepo })
    const uniq = crypto.randomUUID().slice(0, 8)

    const org = await svc.createOrg({ slug: `org-${uniq}`, name: 'Acme' })
    await assertRejects(
      () => svc.createOrg({ slug: `org-${uniq}`, name: 'Acme Again' }),
      Error,
      'slug already exists',
    )

    const { service } = await svc.registerService(org.id, {
      slug: 'app',
      name: 'App',
      audience: `aud-${uniq}`,
      type: 'public',
      redirectUris: [],
    })
    await assertRejects(
      () =>
        svc.registerService(org.id, {
          slug: 'other',
          name: 'Other',
          audience: `aud-${uniq}`,
          type: 'public',
          redirectUris: [],
        }),
      Error,
      'audience already exists',
    )

    await svc.createRole(service.id, 'editor')
    await assertRejects(
      () => svc.createRole(service.id, 'editor'),
      Error,
      'name already exists',
    )

    await svc.createPermission(service.id, 'docs:read')
    await assertRejects(
      () => svc.createPermission(service.id, 'docs:read'),
      Error,
      'key already exists',
    )

    // The constraints are per service, so a second service may reuse both.
    const { service: two } = await svc.registerService(org.id, {
      slug: 'two',
      name: 'Two',
      audience: `aud2-${uniq}`,
      type: 'public',
      redirectUris: [],
    })
    assertEquals((await svc.createRole(two.id, 'editor')).name, 'editor')
    assertEquals(
      (await svc.createPermission(two.id, 'docs:read')).key,
      'docs:read',
    )

    await pool.end()
  },
})
