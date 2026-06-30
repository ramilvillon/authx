import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { googleAuth } from '@hono/oauth-providers/google'
import { describeRoute } from 'hono-openapi'
import { resolver, validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import {
  authorizeFormSchema,
  authorizeQuerySchema,
  revokeSchema,
  tokenPairSchema,
  tokenRequestSchema,
} from './auth.schema.ts'
import { loginPage } from './login-page.ts'

const json = (schema: ReturnType<typeof resolver>) => ({
  'application/json': { schema },
})

const SESSION_COOKIE = 'authx_session'

function redirectTo(
  base: string,
  params: Record<string, string | undefined>,
): string {
  const u = new URL(base)
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) u.searchParams.set(k, v)
  }
  return u.toString()
}

const auth = new Hono<AppEnv>()
  .post(
    '/token',
    describeRoute({
      tags: ['Auth'],
      summary: 'Issue tokens (password or refresh_token grant)',
      responses: {
        200: {
          description: 'A new access/refresh token pair',
          content: json(resolver(tokenPairSchema)),
        },
        400: { description: 'Invalid request body' },
        401: { description: 'Invalid credentials or refresh token' },
      },
    }),
    validator('json', tokenRequestSchema),
    async (c) => {
      const body = c.req.valid('json')
      const svc = c.var.authService
      const pair = body.grant_type === 'password'
        ? await svc.passwordGrant(body.username, body.password, body.audience)
        : body.grant_type === 'refresh_token'
        ? await svc.refreshGrant(body.refresh_token)
        : await svc.exchangeAuthorizationCode({
          code: body.code,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier,
          clientId: body.client_id,
          clientSecret: body.client_secret,
        })
      return c.json(pair, 200)
    },
  )
  .post(
    '/revoke',
    describeRoute({
      tags: ['Auth'],
      summary: 'Revoke a refresh token',
      responses: {
        204: { description: 'Revoked (idempotent)' },
        400: { description: 'Invalid request body' },
      },
    }),
    validator('json', revokeSchema),
    async (c) => {
      await c.var.authService.revoke(c.req.valid('json').refresh_token)
      return c.body(null, 204)
    },
  )
  .get(
    '/authorize',
    validator('query', authorizeQuerySchema),
    async (c) => {
      const q = c.req.valid('query')
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: q.client_id,
        redirectUri: q.redirect_uri,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: q.code_challenge_method,
      })
      const sessionToken = getCookie(c, SESSION_COOKIE)
      const userId = sessionToken
        ? await c.var.authService.userIdForSession(sessionToken)
        : null
      if (!userId) return c.html(loginPage(q))
      const code = await c.var.authService.issueAuthorizationCode(
        userId,
        service,
        {
          redirectUri: q.redirect_uri,
          scope: q.scope,
          codeChallenge: q.code_challenge,
          codeChallengeMethod: q.code_challenge_method,
        },
      )
      return c.redirect(redirectTo(q.redirect_uri, { code, state: q.state }))
    },
  )
  .post(
    '/authorize',
    validator('form', authorizeFormSchema),
    async (c) => {
      const f = c.req.valid('form')
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: f.client_id,
        redirectUri: f.redirect_uri,
        codeChallenge: f.code_challenge,
        codeChallengeMethod: f.code_challenge_method,
      })
      let login: { token: string; userId: string }
      try {
        login = await c.var.authService.loginCreateSession(f.email, f.password)
      } catch {
        return c.html(loginPage(f, 'Invalid email or password'), 401)
      }
      // secure only over https (the issuer's scheme); lets local http dev work.
      setCookie(c, SESSION_COOKIE, login.token, {
        httpOnly: true,
        secure: c.var.config.issuer.startsWith('https'),
        sameSite: 'Lax',
        path: '/',
        maxAge: c.var.config.ssoSessionTtl,
      })
      const code = await c.var.authService.issueAuthorizationCode(
        login.userId,
        service,
        {
          redirectUri: f.redirect_uri,
          scope: f.scope,
          codeChallenge: f.code_challenge,
          codeChallengeMethod: f.code_challenge_method,
        },
      )
      return c.redirect(redirectTo(f.redirect_uri, { code, state: f.state }))
    },
  )
  .post('/logout', async (c) => {
    const sessionToken = getCookie(c, SESSION_COOKIE)
    if (sessionToken) await c.var.authService.logout(sessionToken)
    deleteCookie(c, SESSION_COOKIE, { path: '/' })
    return c.body(null, 204)
  })
  // `googleAuth` handles both initiating the redirect to Google and processing
  // the callback on the same route (the route must equal GOOGLE_REDIRECT_URI).
  .use('/google', (c, next) =>
    googleAuth({
      client_id: c.var.config.google.clientId,
      client_secret: c.var.config.google.clientSecret,
      redirect_uri: c.var.config.google.redirectUri,
      scope: ['openid', 'email', 'profile'],
    })(c, next))
  .get(
    '/google',
    describeRoute({
      tags: ['Auth'],
      summary: 'Google social login (redirect + callback)',
      description:
        'Without an OAuth code, redirects to the Google consent screen. ' +
        'Google redirects back to this same route with a code, which is ' +
        'exchanged for a token pair.',
      responses: {
        200: {
          description: 'Token pair for the Google-authenticated user',
          content: json(resolver(tokenPairSchema)),
        },
        302: { description: 'Redirect to the Google consent screen' },
        400: { description: 'Missing audience query param' },
        401: { description: 'Google profile missing or unverified' },
      },
    }),
    async (c) => {
      const profile = c.get('user-google')
      if (!profile?.id || !profile.email) {
        return c.json(
          { error: { code: 'oauth_failed', message: 'no google profile' } },
          401,
        )
      }
      const audience = c.req.query('audience')
      if (!audience) {
        return c.json(
          { error: { code: 'bad_request', message: 'audience required' } },
          400,
        )
      }
      const pair = await c.var.authService.loginWithGoogle({
        providerAccountId: profile.id,
        email: profile.email,
        emailVerified: profile.verified_email ?? false,
      }, audience)
      return c.json(pair, 200)
    },
  )

export default auth
