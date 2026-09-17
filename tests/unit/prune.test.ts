import { assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps, seedDefaultService } from '../helpers.ts'
import { pruneExpired } from '../../src/db/prune.ts'
import { generateRefreshToken, hashToken } from '../../src/lib/tokens.ts'

const days = (n: number) => n * 86400 * 1000

Deno.test('pruning removes rows expired longer ago than the retention window, and only those', async () => {
  const ctx = makeTestDeps()
  const now = Date.now()
  // expiresAt is already TTL-relative, so "expired more than N ago" is the
  // whole rule -- no need to know what TTL minted the row.
  await ctx.tokenRepo.create({
    id: 'old',
    userId: 'u1',
    appServiceId: 's1',
    tokenHash: 'h-old',
    expiresAt: new Date(now - days(40)),
  })
  await ctx.tokenRepo.create({
    id: 'recent',
    userId: 'u1',
    appServiceId: 's1',
    tokenHash: 'h-recent',
    expiresAt: new Date(now - days(10)),
  })
  await ctx.tokenRepo.create({
    id: 'live',
    userId: 'u1',
    appServiceId: 's1',
    tokenHash: 'h-live',
    expiresAt: new Date(now + days(10)),
  })

  const counts = await pruneExpired(ctx, new Date(now - days(30)))

  assertEquals(counts.refreshTokens, 1)
  assertEquals(await ctx.tokenRepo.findByHash('h-old'), null)
  assertEquals(!!(await ctx.tokenRepo.findByHash('h-recent')), true)
  assertEquals(!!(await ctx.tokenRepo.findByHash('h-live')), true)
})

Deno.test('a dead row inside the retention window is kept, so reuse detection still fires', async () => {
  const ctx = makeTestDeps()
  const { authService, userService } = ctx.deps
  const user = await userService.register({
    email: 'a@b.com',
    password: 'pw123456',
  })
  await seedDefaultService(ctx.orgRepo, user.id)

  // A token that is both revoked and expired, but only recently: the exact row
  // a naive "delete what has expired" prune would remove.
  const stolen = generateRefreshToken()
  await ctx.tokenRepo.create({
    id: 'rt-stolen',
    userId: user.id,
    appServiceId: 's1',
    tokenHash: await hashToken(stolen),
    expiresAt: new Date(Date.now() - days(10)),
  })
  await ctx.tokenRepo.revoke('rt-stolen')

  await pruneExpired(ctx, new Date(Date.now() - days(30)))

  // refreshGrant checks revokedAt BEFORE expiry, so this row is what turns a
  // replay into "theft, revoke the family". Prune it and the replay degrades
  // to an unremarkable unknown-token 401 with no family revocation.
  await assertRejects(
    () => authService.refreshGrant(stolen),
    Error,
    'refresh token reuse',
  )
})
