import { assert, assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

function register(app: ReturnType<typeof makeTestApp>['app'], email: string) {
  return app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'pw123456' }),
  })
}

Deno.test('register -> verify link -> email_verified true', async () => {
  const ctx = makeTestApp()
  const res = await register(ctx.app, 'a@b.com')
  assertEquals(res.status, 201)
  assertEquals(ctx.sentEmails.length, 1)
  const link = ctx.sentEmails[0].link
  const token = new URL(link).searchParams.get('token')!

  const verify = await ctx.app.request(`/verify-email?token=${token}`)
  assertEquals(verify.status, 200)
  assert((await verify.text()).length > 0) // HTML confirmation

  const user = await ctx.userRepo.findByEmail('a@b.com')
  assertEquals(user?.emailVerified, true)
})

Deno.test('a replayed verification link renders an error page (non-200)', async () => {
  const ctx = makeTestApp()
  await register(ctx.app, 'a@b.com')
  const token = new URL(ctx.sentEmails[0].link).searchParams.get('token')!
  await ctx.app.request(`/verify-email?token=${token}`)
  const replay = await ctx.app.request(`/verify-email?token=${token}`)
  assertEquals(replay.status, 400)
})

Deno.test('resend returns 204 for both unknown and existing emails (indistinguishable)', async () => {
  const ctx = makeTestApp()
  await register(ctx.app, 'a@b.com')
  const body = (email: string) => ({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  })
  const known = await ctx.app.request('/verify-email/resend', body('a@b.com'))
  const unknown = await ctx.app.request(
    '/verify-email/resend',
    body('nobody@b.com'),
  )
  assertEquals(known.status, 204)
  assertEquals(unknown.status, 204)
})
