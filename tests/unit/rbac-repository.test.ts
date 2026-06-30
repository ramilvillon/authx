import { assertEquals } from '@std/assert'
import { createInMemoryRbacRepository } from '../../src/modules/rbac/rbac.repository.ts'

Deno.test('permissions are scoped to a service', async () => {
  const repo = createInMemoryRbacRepository()
  // billing service: admin -> billing:read
  await repo.createRole({ id: 'r1', appServiceId: 's1', name: 'admin' })
  await repo.createPermission({
    id: 'p1',
    appServiceId: 's1',
    key: 'billing:read',
  })
  await repo.grantPermissionToRole('r1', 'p1')
  // analytics service: viewer -> analytics:read
  await repo.createRole({ id: 'r2', appServiceId: 's2', name: 'viewer' })
  await repo.createPermission({
    id: 'p2',
    appServiceId: 's2',
    key: 'analytics:read',
  })
  await repo.grantPermissionToRole('r2', 'p2')

  await repo.assignRoleToUser('u1', 'r1')
  await repo.assignRoleToUser('u1', 'r2')

  assertEquals(await repo.permissionsForUserInService('u1', 's1'), [
    'billing:read',
  ])
  assertEquals(await repo.permissionsForUserInService('u1', 's2'), [
    'analytics:read',
  ])
})
