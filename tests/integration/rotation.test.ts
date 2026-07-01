import { assert, assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'
import { authHeader, seedDefaultService } from '../helpers.ts'

Deno.test('jwks serves the active key and a password-grant token is accepted by requireAuth', async () => {
  const { app, userRepo, orgRepo } = makeTestApp()
  const now = new Date()
  const user = await userRepo.create({
    id: crypto.randomUUID(),
    email: 'a@b.com',
    passwordHash: await (await import('../../src/lib/password.ts'))
      .hashPassword('pw123456'),
    createdAt: now,
    updatedAt: now,
  })
  const audience = await seedDefaultService(orgRepo, user.id, 'rot-svc')

  const jwks = await (await app.request('/.well-known/jwks.json')).json()
  assert(jwks.keys.length >= 1)
  assert(typeof jwks.keys[0].kid === 'string')

  const h = await authHeader(app, 'a@b.com', 'pw123456', audience)
  const me = await app.request('/users/me', { headers: h })
  assertEquals(me.status, 200)
})
