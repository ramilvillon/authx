import { assertEquals } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleRbacRepository } from '../../src/modules/rbac/rbac.repository.drizzle.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))

Deno.test({
  name:
    'drizzle client_roles grant + permissionsForClientInService (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleRbacRepository(db)
    const svc = crypto.randomUUID()
    const client = crypto.randomUUID()
    const role = crypto.randomUUID()
    const perm = crypto.randomUUID()
    await repo.createRole({ id: role, appServiceId: svc, name: 'writer' })
    await repo.createPermission({
      id: perm,
      appServiceId: svc,
      key: 'orders:write',
    })
    await repo.grantPermissionToRole(role, perm)
    await repo.assignRoleToClient(client, role)
    assertEquals(await repo.permissionsForClientInService(client, svc), [
      'orders:write',
    ])
    await pool.end()
  },
})
