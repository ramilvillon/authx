import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

// The rest of the suite calls `loginWithGoogle` directly, so nothing exercises
// the `googleAuth` middleware mounted at `/oauth/google`. These tests drive the
// real route: the middleware decides initiate-vs-callback, checks `state`, and
// redeems the code, and all of that was previously untested.

const GOOGLE_ENV = {
  GOOGLE_CLIENT_ID: 'test-client-id',
  GOOGLE_CLIENT_SECRET: 'test-client-secret',
  GOOGLE_REDIRECT_URI: 'http://localhost/oauth/google',
}

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
const USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v2/userinfo'

// Replaces global fetch so the middleware's two calls to Google resolve without
// network. `calls` is the assertion surface: an untouched Google means the
// authorization code was never redeemed.
function stubGoogle(profile: Record<string, unknown>) {
  const calls: string[] = []
  const real = globalThis.fetch
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url
    calls.push(url)
    if (url.startsWith(TOKEN_ENDPOINT)) {
      return Promise.resolve(
        Response.json({
          access_token: 'google-access-token',
          expires_in: 3600,
          scope: 'openid email profile',
          token_type: 'Bearer',
          id_token: 'google-id-token',
        }),
      )
    }
    if (url.startsWith(USERINFO_ENDPOINT)) {
      return Promise.resolve(Response.json(profile))
    }
    throw new Error(`unexpected fetch to ${url}`)
  }) as typeof fetch
  return { calls, restore: () => globalThis.fetch = real }
}

// Everything the browser would send back on the next request.
const cookieHeader = (res: Response) =>
  res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')

Deno.test('GET /oauth/google without a code redirects to Google carrying a state that is also set as a cookie', async () => {
  const { app } = makeTestApp(GOOGLE_ENV)

  const res = await app.request('/oauth/google?audience=test-service')

  assertEquals(res.status, 302)
  const location = res.headers.get('location') ?? ''
  assertStringIncludes(location, 'https://accounts.google.com/o/oauth2/v2/auth')
  const state = new URL(location).searchParams.get('state')
  assert(state, 'the consent redirect must carry a state param')
  assertStringIncludes(cookieHeader(res), `state=${state}`)
})

Deno.test('GET /oauth/google refuses a callback that carries no state at all', async () => {
  const { app, socialRepo } = makeTestApp(GOOGLE_ENV)
  // An attacker's own Google identity, attached to a code they hand to a victim.
  const google = stubGoogle({
    id: 'g-attacker',
    email: 'attacker@evil.test',
    verified_email: true,
  })

  try {
    // No state query param, and no state cookie: the victim's browser never
    // initiated a login. Comparing two absent values must not read as a match.
    const res = await app.request(
      '/oauth/google?code=attacker-code&audience=test-service',
    )

    // This is the security property, and it is asserted first because it is the
    // one that actually distinguishes a rejected callback from an accepted one.
    // A redeemed code means the attacker's identity was already exchanged with
    // Google before anything downstream got a say.
    assertEquals(
      google.calls,
      [],
      'the authorization code must never reach Google',
    )
    assertEquals(
      res.status,
      401,
      'a callback with neither a state param nor a state cookie must be refused',
    )
    assertEquals(
      await socialRepo.findByProviderAccount('google', 'g-attacker'),
      null,
      'no social account may be linked from an unverified callback',
    )
  } finally {
    google.restore()
  }
})

Deno.test('GET /oauth/google refuses a callback whose state does not match the cookie', async () => {
  const { app } = makeTestApp(GOOGLE_ENV)
  const initiate = await app.request('/oauth/google?audience=test-service')
  const google = stubGoogle({
    id: 'g-1',
    email: 'u@example.test',
    verified_email: true,
  })

  try {
    const res = await app.request(
      '/oauth/google?code=some-code&state=not-the-minted-one',
      {
        headers: { cookie: cookieHeader(initiate) },
      },
    )

    assertEquals(res.status, 401)
    assertEquals(
      google.calls,
      [],
      'the authorization code must never reach Google',
    )
  } finally {
    google.restore()
  }
})

Deno.test('the audience query param does not survive the Google round trip', async () => {
  const { app } = makeTestApp(GOOGLE_ENV)

  const initiate = await app.request('/oauth/google?audience=test-service')
  const state = new URL(initiate.headers.get('location') ?? '').searchParams
    .get('state')
  assert(state)

  // Google redirects to the exact registered GOOGLE_REDIRECT_URI and echoes back
  // only `code` and `state` — so whatever audience began the flow is gone, and
  // the handler's own `c.req.query('audience')` finds nothing.
  assertEquals(
    new URL(GOOGLE_ENV.GOOGLE_REDIRECT_URI).searchParams.get('audience'),
    null,
    'the registered redirect URI pins no audience',
  )

  const google = stubGoogle({
    id: 'g-1',
    email: 'u@example.test',
    verified_email: true,
  })
  try {
    const res = await app.request(
      `/oauth/google?code=good-code&state=${state}`,
      {
        headers: { cookie: cookieHeader(initiate) },
      },
    )

    // ponytail: asserts today's broken behaviour so the fix has a tripwire.
    // Carrying the audience through `state` is what closes this; when that
    // lands, this test flips to asserting a 200 and a token pair.
    assertEquals(
      res.status,
      400,
      'the callback cannot know which audience to mint for',
    )
    assertEquals((await res.json()).error.code, 'bad_request')
  } finally {
    google.restore()
  }
})
