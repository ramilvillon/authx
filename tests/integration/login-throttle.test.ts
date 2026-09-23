import { assertEquals } from '@std/assert'
import { makeTestApp, seedDefaultService, submitLoginForm } from '../helpers.ts'

const PASSWORD = 'pw123456'
// Low enough that a test never trips the per-IP login limiter (10/window),
// which would answer 429 and hide what we are actually measuring.
const ENV = { LOGIN_MAX_FAILURES: '3', LOGIN_LOCKOUT_MS: '60000' }

async function setup(env: Record<string, string> = ENV) {
  const ctx = makeTestApp(env)
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: PASSWORD }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  return { ...ctx, user, audience }
}

function login(
  ctx: { app: ReturnType<typeof makeTestApp>['app'] },
  audience: string,
  password: string,
  username = 'a@b.com',
) {
  return ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username,
      password,
      audience,
    }),
  })
}

Deno.test('after the failure limit the correct password is refused too', async () => {
  const ctx = await setup()
  for (let i = 0; i < 3; i++) {
    assertEquals((await login(ctx, ctx.audience, 'wrong')).status, 400)
  }
  const res = await login(ctx, ctx.audience, PASSWORD)
  assertEquals(res.status, 400)
  // Same body as an ordinary wrong password: a distinct code would tell an
  // attacker the account exists, which is the enumeration this avoids.
  assertEquals((await res.json()).error, 'invalid_grant')
})

Deno.test('a success resets the count before the limit is reached', async () => {
  const ctx = await setup()
  for (let i = 0; i < 2; i++) await login(ctx, ctx.audience, 'wrong')
  assertEquals((await login(ctx, ctx.audience, PASSWORD)).status, 200)
  // Counter cleared, so two more failures must not lock the account.
  for (let i = 0; i < 2; i++) await login(ctx, ctx.audience, 'wrong')
  assertEquals((await login(ctx, ctx.audience, PASSWORD)).status, 200)
})

Deno.test('the lockout expires on its own', async () => {
  const ctx = await setup({ LOGIN_MAX_FAILURES: '3', LOGIN_LOCKOUT_MS: '50' })
  for (let i = 0; i < 3; i++) await login(ctx, ctx.audience, 'wrong')
  assertEquals((await login(ctx, ctx.audience, PASSWORD)).status, 400)
  await new Promise((r) => setTimeout(r, 70))
  assertEquals((await login(ctx, ctx.audience, PASSWORD)).status, 200)
})

Deno.test('locking one account leaves another usable', async () => {
  const ctx = await setup()
  const other = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'b@b.com', password: PASSWORD }),
  })).json()
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: other.id,
    orgId: (await ctx.orgRepo.findServiceByAudience(ctx.audience))!.orgId,
    createdAt: new Date(),
  })

  for (let i = 0; i < 3; i++) await login(ctx, ctx.audience, 'wrong')
  assertEquals((await login(ctx, ctx.audience, PASSWORD)).status, 400)
  assertEquals(
    (await login(ctx, ctx.audience, PASSWORD, 'b@b.com')).status,
    200,
  )
})

// The count has to live below both entry points, or an attacker just switches
// endpoints: the SSO login form and the password grant check the same account.
Deno.test('the login form and the password grant share one count', async () => {
  const ctx = await setup()
  const service = (await ctx.orgRepo.findServiceByAudience(ctx.audience))!
  // seedDefaultService registers no redirect URI, and /oauth/authorize refuses
  // the request before it ever reaches the login form without one.
  const redirect = 'https://app.example/cb'
  await ctx.orgRepo.updateService(service.id, { redirectUris: [redirect] })

  const formLogin = (password: string) =>
    submitLoginForm(ctx.app, {
      client_id: service.clientId,
      redirect_uri: redirect,
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
      email: 'a@b.com',
      password,
    })

  // Control: the form accepts the password before any failures are recorded.
  assertEquals((await formLogin(PASSWORD)).status, 302)

  for (let i = 0; i < 3; i++) await login(ctx, ctx.audience, 'wrong')
  // Locked by failures spent on the OTHER endpoint: 401 re-renders the page.
  assertEquals((await formLogin(PASSWORD)).status, 401)
})
