import { assert, assertEquals, assertRejects } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'
import { createVerificationService } from '../../src/modules/verification/verification.service.ts'
import { createInMemoryVerificationTokenRepository } from '../../src/modules/verification/verification.repository.ts'
import type { UserRepository } from '../../src/modules/users/users.repository.ts'

async function seedUser(
  ctx: ReturnType<typeof makeTestDeps>,
  verified = false,
) {
  const now = new Date()
  return await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: 'a@b.com',
    passwordHash: 'h',
    emailVerified: verified,
    createdAt: now,
    updatedAt: now,
  })
}

Deno.test('startVerification sends a well-formed link and verifyEmail sets emailVerified', async () => {
  const ctx = makeTestDeps()
  const user = await seedUser(ctx)
  await ctx.deps.verificationService.startVerification(user.id, user.email)
  assertEquals(ctx.sentEmails.length, 1)
  const link = ctx.sentEmails[0].link
  assert(link.includes('/verify-email?token='))
  const token = new URL(link).searchParams.get('token')!

  await ctx.deps.verificationService.verifyEmail(token)
  assertEquals((await ctx.userRepo.findById(user.id))?.emailVerified, true)
})

Deno.test('verifyEmail rejects an unknown, replayed, or email-mismatched token', async () => {
  const ctx = makeTestDeps()
  const user = await seedUser(ctx)
  const throws = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      return false
    } catch {
      return true
    }
  }
  assert(await throws(() => ctx.deps.verificationService.verifyEmail('nope')))

  await ctx.deps.verificationService.startVerification(user.id, user.email)
  const token = new URL(ctx.sentEmails[0].link).searchParams.get('token')!
  await ctx.deps.verificationService.verifyEmail(token) // consumes
  assert(await throws(() => ctx.deps.verificationService.verifyEmail(token))) // replay

  // email changed since the link was issued -> stale link rejected
  await ctx.deps.verificationService.startVerification(user.id, user.email)
  const t2 = new URL(ctx.sentEmails[1].link).searchParams.get('token')!
  await ctx.userRepo.update(user.id, { email: 'changed@b.com' })
  assert(await throws(() => ctx.deps.verificationService.verifyEmail(t2)))
})

Deno.test('verifyEmail does not verify an address swapped in after the binding check', async () => {
  const ctx = makeTestDeps()
  const user = await seedUser(ctx)
  const links: string[] = []
  // Commits the attacker's email change in the window between the service's
  // read of the user and its write — the TOCTOU the compare-and-set closes.
  const racingUserRepo: UserRepository = {
    ...ctx.userRepo,
    async findById(id) {
      const snapshot = await ctx.userRepo.findById(id)
      await ctx.userRepo.update(id, {
        email: 'ceo@target.com',
        emailVerified: false,
      })
      return snapshot
    },
  }
  const service = createVerificationService({
    verificationRepo: createInMemoryVerificationTokenRepository(),
    userRepo: racingUserRepo,
    emailSender: {
      sendVerificationEmail: (_to: string, link: string) => {
        links.push(link)
        return Promise.resolve()
      },
    },
    config: ctx.deps.config,
  })

  await service.startVerification(user.id, user.email)
  const token = new URL(links[0]).searchParams.get('token')!
  await assertRejects(() => service.verifyEmail(token))
  const after = await ctx.userRepo.findById(user.id)
  assertEquals(after?.email, 'ceo@target.com')
  assertEquals(after?.emailVerified, false)
})

Deno.test('resend uses the stored address, so a case-differing request still yields a usable link', async () => {
  const ctx = makeTestDeps()
  const user = await seedUser(ctx)
  // ponytail: MySQL's collation matches case-insensitively; the in-memory repo
  // is exact, so fake the production lookup here rather than change the double.
  const exact = ctx.userRepo.findByEmail
  ctx.userRepo.findByEmail = (email) => exact(email.toLowerCase())

  await ctx.deps.verificationService.resend('A@B.com')
  assertEquals(ctx.sentEmails[0].to, user.email)
  const token = new URL(ctx.sentEmails[0].link).searchParams.get('token')!
  await ctx.deps.verificationService.verifyEmail(token) // must not throw
  assertEquals((await ctx.userRepo.findById(user.id))?.emailVerified, true)
})

Deno.test('resend is a no-op for unknown or already-verified emails (no throw, no send)', async () => {
  const ctx = makeTestDeps()
  await ctx.deps.verificationService.resend('nobody@b.com')
  assertEquals(ctx.sentEmails.length, 0)
  await seedUser(ctx, true) // verified
  await ctx.deps.verificationService.resend('a@b.com')
  assertEquals(ctx.sentEmails.length, 0)
})
