import { assert, assertEquals } from '@std/assert'
import { createInMemoryOrgRepository } from '../../src/modules/orgs/orgs.repository.ts'

function now() {
  return new Date()
}

Deno.test('org + service + membership round-trips', async () => {
  const repo = createInMemoryOrgRepository()
  const org = await repo.createOrg({
    id: 'o1',
    slug: 'acme',
    name: 'Acme',
    createdAt: now(),
  })
  assertEquals((await repo.findOrgById('o1'))?.slug, 'acme')

  await repo.createService({
    id: 's1',
    orgId: org.id,
    clientId: 'cid_1',
    clientSecretHash: null,
    name: 'Billing',
    slug: 'billing',
    audience: 'acme-billing',
    type: 'public',
    redirectUris: [],
    createdAt: now(),
  })
  assertEquals((await repo.findServiceByAudience('acme-billing'))?.id, 's1')
  assertEquals((await repo.listServicesByOrg('o1')).length, 1)

  await repo.addMember({
    id: 'm1',
    userId: 'u1',
    orgId: 'o1',
    createdAt: now(),
  })
  assert(await repo.isMember('u1', 'o1'))
  await repo.removeMember('u1', 'o1')
  assert(!(await repo.isMember('u1', 'o1')))
})

Deno.test('findServiceByClientId resolves the service', async () => {
  const repo = createInMemoryOrgRepository()
  await repo.createOrg({
    id: 'o9',
    slug: 'o9',
    name: 'O9',
    createdAt: new Date(),
  })
  await repo.createService({
    id: 's9',
    orgId: 'o9',
    clientId: 'cid_9',
    clientSecretHash: null,
    name: 'S9',
    slug: 's9',
    audience: 'aud9',
    type: 'public',
    redirectUris: ['https://app.example/cb'],
    createdAt: new Date(),
  })
  assertEquals((await repo.findServiceByClientId('cid_9'))?.id, 's9')
  assertEquals(await repo.findServiceByClientId('missing'), null)
})
