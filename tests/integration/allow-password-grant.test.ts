import { assert, assertEquals } from '@std/assert'
import { makeTestApp, seedDefaultService, submitLoginForm } from '../helpers.ts'

async function setup(env: Record<string, string>) {
  const ctx = makeTestApp(env)
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const grant = (password = 'pw123456') =>
    ctx.app.request('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: 'a@b.com',
        password,
        audience,
      }),
    })
  return { ...ctx, audience, grant }
}

async function grantTypes(app: ReturnType<typeof makeTestApp>['app']) {
  return (await (await app.request('/.well-known/openid-configuration'))
    .json()).grant_types_supported as string[]
}

Deno.test('the password grant works and is advertised when enabled', async () => {
  const ctx = await setup({})
  assertEquals((await ctx.grant()).status, 200)
  assert((await grantTypes(ctx.app)).includes('password'))
})

Deno.test('ALLOW_PASSWORD_GRANT=false refuses the grant as unsupported, even with the right password', async () => {
  const ctx = await setup({ ALLOW_PASSWORD_GRANT: 'false' })
  const res = await ctx.grant()
  assertEquals(res.status, 400)
  assertEquals((await res.json()).error, 'unsupported_grant_type')
  assert(!(await grantTypes(ctx.app)).includes('password'))
})

// The refusal comes before the lookup, so hammering a disabled grant cannot
// lock anyone out through the per-account throttle the login form shares.
Deno.test('a disabled password grant does not count toward the login throttle', async () => {
  const ctx = await setup({
    ALLOW_PASSWORD_GRANT: 'false',
    LOGIN_MAX_FAILURES: '2',
  })
  for (let i = 0; i < 3; i++) await (await ctx.grant('wrong')).body?.cancel()

  const service = (await ctx.orgRepo.findServiceByAudience(ctx.audience))!
  const redirect = 'https://app.example/cb'
  await ctx.orgRepo.updateService(service.id, { redirectUris: [redirect] })
  const res = await submitLoginForm(ctx.app, {
    client_id: service.clientId,
    redirect_uri: redirect,
    code_challenge: 'x'.repeat(43),
    code_challenge_method: 'S256',
    email: 'a@b.com',
    password: 'pw123456',
  })
  assertEquals(res.status, 302)
})
