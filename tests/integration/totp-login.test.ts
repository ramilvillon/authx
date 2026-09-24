import { assertEquals, assertStringIncludes } from '@std/assert'
import {
  authHeader,
  makeTestApp,
  seedDefaultService,
  totpCode,
} from '../helpers.ts'

const PASSWORD = 'pw123456'

async function setup(env: Record<string, string> = {}) {
  const ctx = makeTestApp(env)
  const email = `l-${crypto.randomUUID()}@b.com`
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  return { ...ctx, user, email, audience }
}

// Trap: once TOTP is on, authHeader can no longer mint a token for that user
// (the grant answers mfa_required). A test that needs the user's API token
// after enrolling must mint it BEFORE enroll.
// Enrolls through the API with a token obtained BEFORE TOTP was on.
async function enroll(ctx: Awaited<ReturnType<typeof setup>>) {
  const { Authorization } = await authHeader(
    ctx.app,
    ctx.email,
    PASSWORD,
    ctx.audience,
  )
  const headers = { Authorization, 'content-type': 'application/json' }
  const { secret } = await (await ctx.app.request('/users/me/totp', {
    method: 'POST',
    headers,
  })).json()
  const { recovery_codes } =
    await (await ctx.app.request('/users/me/totp/confirm', {
      method: 'POST',
      headers,
      body: JSON.stringify({ code: await totpCode(secret) }),
    })).json()
  return {
    secret: secret as string,
    recovery_codes: recovery_codes as string[],
  }
}

function passwordGrant(
  ctx: Awaited<ReturnType<typeof setup>>,
  password: string,
) {
  return ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: ctx.email,
      password,
      audience: ctx.audience,
    }),
  })
}

Deno.test('password grant: a TOTP user with the right password gets mfa_required', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const res = await passwordGrant(ctx, PASSWORD)
  assertEquals(res.status, 400)
  const body = await res.json()
  assertEquals(body.error, 'mfa_required')
  assertStringIncludes(body.error_description, 'authorization code flow')
})

Deno.test('password grant: a wrong password is still invalid_grant for a TOTP user', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const res = await passwordGrant(ctx, 'wrong-password')
  assertEquals((await res.json()).error, 'invalid_grant')
})
