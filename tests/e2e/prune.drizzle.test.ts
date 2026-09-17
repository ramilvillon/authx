import { assert, assertEquals } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createDb } from '../../src/db/client.ts'
import { createDrizzleVerificationTokenRepository } from '../../src/modules/verification/verification.repository.drizzle.ts'
import { createDrizzleUserRepository } from '../../src/modules/users/users.repository.drizzle.ts'

const hasDb = Boolean(Deno.env.get('DB_NAME'))
const days = (n: number) => n * 86400 * 1000

// The in-memory doubles compare Dates in JS; the real repository compares a
// datetime column in MySQL. This is the only place that gets exercised.
Deno.test({
  name:
    'drizzle deleteExpiredBefore removes only rows past the cutoff (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleVerificationTokenRepository(db)
    const userId = crypto.randomUUID()
    const mk = async (label: string, expiresAt: Date) => {
      const tokenHash = crypto.randomUUID().replace(/-/g, '') +
        label.slice(0, 2)
      await repo.create({
        id: crypto.randomUUID(),
        userId,
        email: 'a@b.com',
        purpose: 'verify_email',
        tokenHash,
        expiresAt,
      })
      return tokenHash
    }
    const old = await mk('old', new Date(Date.now() - days(40)))
    const recent = await mk('recent', new Date(Date.now() - days(10)))
    const live = await mk('live', new Date(Date.now() + days(10)))

    const removed = await repo.deleteExpiredBefore(
      new Date(Date.now() - days(30)),
    )

    assert(removed >= 1, 'the long-expired row must be removed')
    assertEquals(await repo.findByHash(old), null)
    // Inside the retention window: still readable, which is what keeps replay
    // detection working.
    assert(await repo.findByHash(recent))
    assert(await repo.findByHash(live))

    await repo.deleteAllForUser(userId)
    await pool.end()
  },
})

// The in-memory double filters in JS; the real repository filters with
// `deleted_at IS NULL` in MySQL. Only this test exercises that.
Deno.test({
  name:
    'drizzle soft delete hides the row from every ordinary lookup (needs MySQL)',
  ignore: !hasDb,
  fn: async () => {
    const { db, pool } = createDb(loadConfig(Deno.env.toObject()))
    const repo = createDrizzleUserRepository(db)
    const now = new Date()
    const email = `soft-${crypto.randomUUID()}@b.com`
    const user = await repo.create({
      id: crypto.randomUUID(),
      email,
      passwordHash: null,
      createdAt: now,
      updatedAt: now,
    })

    assert(await repo.findById(user.id))
    assert(await repo.softDelete(user.id))

    assertEquals(await repo.findById(user.id), null)
    assertEquals(await repo.findByEmail(email), null)
    assertEquals(await repo.findWithAccessById(user.id), null)
    // Unfiltered on purpose: the UNIQUE constraint still holds the address, so
    // registration has to be able to see it.
    assert(await repo.findAnyByEmail(email))
    // A second soft delete is a no-op, not a second row touched.
    assertEquals(await repo.softDelete(user.id), false)

    const ids = await repo.findDeletedBefore(new Date(Date.now() + 60_000))
    assert(ids.includes(user.id))

    await repo.delete(user.id)
    await pool.end()
  },
})
