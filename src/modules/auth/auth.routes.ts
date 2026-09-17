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
import { AppError } from '../../lib/errors.ts'
import { generateRefreshToken } from '../../lib/tokens.ts'
import type { Context } from 'hono'
import type { z } from 'zod'

const json = (schema: ReturnType<typeof resolver>) => ({
  'application/json': { schema },
})

const SESSION_COOKIE = 'authx_session'
const CSRF_COOKIE = 'authx_csrf'
// The authorize request a Google login resumes. Google echoes back only `code`
// and `state`, and `state` belongs to googleAuth, so the request rides in a
// cookie of our own, scoped to the one route that reads it.
const GOOGLE_AUTHORIZE_COOKIE = 'authx_google_authorize'
const GOOGLE_PATH = '/oauth/google'

type AuthorizeQuery = z.infer<typeof authorizeQuerySchema>

// Double-submit: the same random value in a cookie and in a hidden form field.
// An attacker's page can forge the field but cannot read or write a cookie on
// this origin, so it cannot make the two agree — which is what stops a
// drive-by POST from logging a victim into the attacker's account.
//
// Reuse an existing cookie instead of minting per render. Re-minting was what
// broke the previous attempt: every render would invalidate the field the last
// one handed out, killing two open tabs, the back button, and the
// wrong-password retry (which re-renders this very page).
function csrfToken(c: Context<AppEnv>): string {
  const token = getCookie(c, CSRF_COOKIE) ?? generateRefreshToken()
  setCookie(c, CSRF_COOKIE, token, {
    httpOnly: true,
    // secure only over https (the issuer's scheme); lets local http dev work.
    secure: c.var.config.issuer.startsWith('https'),
    sameSite: 'Lax',
    path: '/',
    maxAge: 3600,
  })
  return token
}

const secureCookies = (c: Context<AppEnv>) =>
  c.var.config.issuer.startsWith('https')

function setSessionCookie(c: Context<AppEnv>, token: string) {
  // secure only over https (the issuer's scheme); lets local http dev work.
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: secureCookies(c),
    sameSite: 'Lax',
    path: '/',
    maxAge: c.var.config.ssoSessionTtl,
  })
}

// Only the authorize parameters: `q` may be a submitted form that also holds
// the email and password, and none of that belongs in a link.
function googleHref(c: Context<AppEnv>, q: AuthorizeQuery): string | undefined {
  if (!c.var.config.google.clientId) return undefined
  const { client_id, redirect_uri, scope, state, nonce } = q
  const params = new URLSearchParams({
    client_id,
    redirect_uri,
    scope,
    code_challenge: q.code_challenge,
    code_challenge_method: q.code_challenge_method,
  })
  if (state) params.set('state', state)
  if (nonce) params.set('nonce', nonce)
  return `${GOOGLE_PATH}?${params}`
}

function renderLogin(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
  error?: string,
  status: 200 | 400 | 401 | 403 | 404 | 409 = 200,
) {
  return c.html(
    loginPage({ ...q, csrf_token: csrfToken(c) }, error, googleHref(c, q)),
    status,
  )
}

function pendingGoogleAuthorize(c: Context<AppEnv>): AuthorizeQuery | null {
  try {
    const parsed = authorizeQuerySchema.safeParse(
      JSON.parse(getCookie(c, GOOGLE_AUTHORIZE_COOKIE) ?? ''),
    )
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

// What the person at the login page is told when Google sign-in is refused.
// account_exists_link_password deliberately covers two cases; keep one message.
const GOOGLE_LOGIN_MESSAGES: Partial<Record<string, string>> = {
  google_email_unverified:
    "Your Google account's email address is not verified.",
  account_exists_link_password:
    'An account with this email already exists. Sign in with your password.',
}

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
        : body.grant_type === 'authorization_code'
        ? await svc.exchangeAuthorizationCode({
          code: body.code,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier,
          clientId: body.client_id,
          clientSecret: body.client_secret,
        })
        : await svc.clientCredentialsGrant(
          body.client_id,
          body.client_secret,
          body.audience,
        )
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
      const session = sessionToken
        ? await c.var.authService.resolveSession(sessionToken)
        : null
      if (!session) return renderLogin(c, q)
      const code = await c.var.authService.issueAuthorizationCode(
        session.userId,
        service,
        {
          redirectUri: q.redirect_uri,
          scope: q.scope,
          codeChallenge: q.code_challenge,
          codeChallengeMethod: q.code_challenge_method,
          nonce: q.nonce,
          authTime: session.authTime,
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
      const presented = getCookie(c, CSRF_COOKIE)
      if (!presented || f.csrf_token !== presented) {
        // A human gets the form back and simply retries. A script gets the
        // machine-readable code instead: handing it a login page makes a
        // protocol mistake look like bad credentials, and it would retry a
        // login that can never succeed.
        if (!c.req.header('accept')?.includes('text/html')) {
          throw AppError.of('csrf_token_invalid')
        }
        // Re-render rather than dead-end: csrfToken reuses the cookie, so a
        // legitimate caller whose cookie was missing gets a working form back.
        return renderLogin(
          c,
          f,
          'This sign-in form is no longer valid. Please try again.',
          403,
        )
      }
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
        return renderLogin(c, f, 'Invalid email or password', 401)
      }
      setSessionCookie(c, login.token)
      const code = await c.var.authService.issueAuthorizationCode(
        login.userId,
        service,
        {
          redirectUri: f.redirect_uri,
          scope: f.scope,
          codeChallenge: f.code_challenge,
          codeChallengeMethod: f.code_challenge_method,
          nonce: f.nonce,
          authTime: new Date(),
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
  // Sign in with Google, as a step of the authorize flow. The login page links
  // here with the pending authorize request; this route remembers it, sends the
  // browser to Google, and on the way back finishes exactly like a password
  // login: SSO session, then an authorization code to the client's redirect_uri.
  // `googleAuth` serves both legs on this one route (it must equal
  // GOOGLE_REDIRECT_URI) and treats any request without a `code` as a start.
  .use('/google', async (c, next) => {
    const google = c.var.config.google
    if (!google.clientId) throw AppError.of('google_login_disabled')
    if (c.req.query('error')) {
      // Cancelled or refused at Google. There is no code, so googleAuth would
      // read this as a fresh start and bounce the user straight back to Google.
      const pending = pendingGoogleAuthorize(c)
      if (!pending) throw AppError.of('authorize_request_expired')
      return renderLogin(c, pending, 'Google sign-in was cancelled.', 401)
    }
    if (!c.req.query('code')) {
      const parsed = authorizeQuerySchema.safeParse(c.req.query())
      if (!parsed.success) throw AppError.of('invalid_request')
      const q = parsed.data
      // Refuse before leaving for Google, so a bad request never gets as far
      // as a consent screen.
      await c.var.authService.validateAuthorizeRequest({
        clientId: q.client_id,
        redirectUri: q.redirect_uri,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: q.code_challenge_method,
      })
      setCookie(c, GOOGLE_AUTHORIZE_COOKIE, JSON.stringify(q), {
        httpOnly: true,
        secure: secureCookies(c),
        sameSite: 'Lax',
        path: GOOGLE_PATH,
        maxAge: 600,
      })
    }
    return googleAuth({
      client_id: google.clientId,
      client_secret: google.clientSecret,
      redirect_uri: google.redirectUri,
      scope: ['openid', 'email', 'profile'],
    })(c, next)
  })
  .get(
    '/google',
    describeRoute({
      tags: ['Auth'],
      summary: 'Sign in with Google (part of the authorize flow)',
      description:
        'Linked from the /oauth/authorize login page with the same query ' +
        'parameters. Redirects to Google; Google redirects back here, and the ' +
        'user is signed in and sent to redirect_uri with an authorization ' +
        'code, as after a password login.',
      responses: {
        302: {
          description:
            'To Google (start), or to redirect_uri with code and state (return)',
        },
        400: {
          description:
            'Invalid authorize parameters, or no sign-in in progress on return',
        },
        401: {
          description:
            'Login page with an error: cancelled at Google, bad state, or no profile',
        },
        403: {
          description:
            'Login page with an error: unverified Google email, or an existing account must sign in with its password',
        },
        404: { description: 'Google login is not configured' },
      },
    }),
    async (c) => {
      const pending = pendingGoogleAuthorize(c)
      if (!pending) throw AppError.of('authorize_request_expired')
      // Re-checked rather than trusted: the client may have changed since the
      // request was stored.
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: pending.client_id,
        redirectUri: pending.redirect_uri,
        codeChallenge: pending.code_challenge,
        codeChallengeMethod: pending.code_challenge_method,
      })
      const profile = c.get('user-google')
      if (!profile?.id || !profile.email) {
        return renderLogin(
          c,
          pending,
          'Google did not share an email address.',
          401,
        )
      }
      let login: { token: string; userId: string }
      try {
        login = await c.var.authService.loginWithGoogle({
          providerAccountId: profile.id,
          email: profile.email,
          emailVerified: profile.verified_email ?? false,
        })
      } catch (e) {
        if (!(e instanceof AppError)) throw e
        return renderLogin(
          c,
          pending,
          GOOGLE_LOGIN_MESSAGES[e.code] ??
            'This Google account cannot be used to sign in.',
          e.status === 409 ? 409 : 403,
        )
      }
      deleteCookie(c, GOOGLE_AUTHORIZE_COOKIE, { path: GOOGLE_PATH })
      setSessionCookie(c, login.token)
      const code = await c.var.authService.issueAuthorizationCode(
        login.userId,
        service,
        {
          redirectUri: pending.redirect_uri,
          scope: pending.scope,
          codeChallenge: pending.code_challenge,
          codeChallengeMethod: pending.code_challenge_method,
          nonce: pending.nonce,
          authTime: new Date(),
        },
      )
      return c.redirect(
        redirectTo(pending.redirect_uri, { code, state: pending.state }),
      )
    },
  )

export default auth
