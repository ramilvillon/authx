import { Hono } from 'hono'
import { createMiddleware } from 'hono/factory'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { AppError } from '../../lib/errors.ts'
import { csrfOnlySchema, passkeyFormSchema } from '../auth/auth.schema.ts'
import {
  csrfRefused,
  finishHostedLogin,
  renderLogin,
  requireCsrf,
} from '../auth/hosted.ts'

const PASSKEY_FAILED = "That passkey couldn't be used."

// First on every passkey route: with passkeys off the routes must look
// absent (404), not forbidden -- so this runs before the CSRF check.
const passkeysOn = createMiddleware<AppEnv>(async (c, next) => {
  if (!c.var.passkeyService.enabled) {
    throw AppError.of('passkey_not_configured')
  }
  await next()
})

// The assertion arrives as a JSON string in a form field. Anything that is
// not JSON is just another unusable passkey.
export function parseCredential(s: string): unknown {
  try {
    return JSON.parse(s)
  } catch {
    throw AppError.of('passkey_invalid')
  }
}

// Mounted at /oauth. Both routes sit under the login IP limiter (app.ts).
const passkeys = new Hono<AppEnv>()
  .post(
    '/authorize/passkey/options',
    passkeysOn,
    validator('form', csrfOnlySchema),
    async (c) => {
      requireCsrf(c, c.req.valid('form').csrf_token)
      return c.json(await c.var.passkeyService.signInOptions(), 200)
    },
  )
  .post(
    '/authorize/passkey',
    passkeysOn,
    validator('form', passkeyFormSchema),
    async (c) => {
      const f = c.req.valid('form')
      const refused = csrfRefused(c, f, f.csrf_token)
      if (refused) return refused
      // Re-checked rather than trusted: the fields came back from the browser.
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: f.client_id,
        redirectUri: f.redirect_uri,
        codeChallenge: f.code_challenge,
        codeChallengeMethod: f.code_challenge_method,
      })
      let session: { token: string; userId: string }
      try {
        const userId = await c.var.passkeyService.verifySignIn(
          parseCredential(f.credential),
        )
        session = await c.var.authService.createPasskeySession(userId)
      } catch (err) {
        if (!(err instanceof AppError)) throw err
        // Only reachable with a valid passkey, so it reveals nothing.
        if (err.code === 'email_not_verified') {
          return renderLogin(
            c,
            f,
            'Please verify your email address before signing in. ' +
              'Check your inbox for the link, or request a new one.',
            403,
          )
        }
        return renderLogin(c, f, PASSKEY_FAILED, 401)
      }
      return finishHostedLogin(c, f, service, session)
    },
  )

export default passkeys
