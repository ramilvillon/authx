import { assert, assertEquals } from '@std/assert'
import { makeTestDeps } from '../helpers.ts'

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

Deno.test('resend is a no-op for unknown or already-verified emails (no throw, no send)', async () => {
  const ctx = makeTestDeps()
  await ctx.deps.verificationService.resend('nobody@b.com')
  assertEquals(ctx.sentEmails.length, 0)
  await seedUser(ctx, true) // verified
  await ctx.deps.verificationService.resend('a@b.com')
  assertEquals(ctx.sentEmails.length, 0)
})
