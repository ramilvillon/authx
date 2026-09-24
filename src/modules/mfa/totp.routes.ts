import { Hono } from 'hono'
import { z } from 'zod'
import { describeRoute } from 'hono-openapi'
import { validator } from 'hono-openapi/zod'
import { createMiddleware } from 'hono/factory'
import type { AppEnv } from '../../deps.ts'
import { requireAuth } from '../../middleware/auth.ts'
import { requirePermission } from '../../middleware/authorize.ts'
import { makeRateLimiter } from '../../middleware/rate-limit.ts'
import { throttleFailedPasswordProofs } from '../users/users.routes.ts'

// Same shape and reasoning as throttleFailedPasswordProofs in users.routes.ts:
// registered after requireAuth so the key is the user id, counting only 401s.
// Without it a stolen bearer token could guess its way to turning 2FA off.
const throttleFailedTotpProofs = createMiddleware<AppEnv>((c, next) =>
  makeRateLimiter(c.var.rateStore, {
    windowMs: c.var.config.rateLimit.windowMs,
    limit: 5,
    prefix: 'totp-proof',
    countOnly: (status) => status === 401,
  })(c, next)
)

// The setup and confirm bodies carry secrets (the TOTP seed, the recovery
// codes): keep them out of every cache, as the token endpoint does.
const noStore = createMiddleware<AppEnv>(async (c, next) => {
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
  await next()
})

const codeSchema = z.object({ code: z.string().min(1).max(64) })
// Optional: a passwordless account proves itself with a fresh sign-in instead.
const setupSchema = z.object({ current_password: z.string().min(1).optional() })
const disableSchema = z.object({
  code: z.string().min(1).max(64).optional(),
  recovery_code: z.string().min(1).max(64).optional(),
}).refine(
  (b) => (b.code === undefined) !== (b.recovery_code === undefined),
  'send exactly one of code or recovery_code',
)

const NOT_CONFIGURED = 'Two-factor authentication is not configured, or the ' +
  'token names no user (a service token)'

// Mounted at /users. Everything here acts on the token's own subject, except
// the operator reset, which is permission-only on purpose: a user turning off
// their own TOTP goes through DELETE /me/totp and presents proof.
const totp = new Hono<AppEnv>()
  .post(
    '/me/totp',
    describeRoute({
      tags: ['Users'],
      summary: 'Start two-factor (TOTP) setup',
      description:
        'Returns a new secret and its otpauth:// URI (render it as ' +
        'a QR code). Nothing is enforced until POST /users/me/totp/confirm. ' +
        'Calling this again replaces a setup that was never confirmed. ' +
        'Needs the current password: an access token alone is not enough, ' +
        'since any app the user is signed into holds one. An account with no ' +
        'password (Google-only) instead needs a token from a sign-in in the ' +
        'last 5 minutes: send the user through /oauth/authorize with ' +
        'prompt=login, then call this with the new token.',
      security: [{ bearerAuth: [] }],
      responses: {
        200: { description: '{ secret, otpauth_uri }' },
        400: {
          description: 'Missing current_password (account has a password)',
        },
        401: {
          description:
            'Missing or invalid access token, or a wrong current_password',
        },
        403: {
          description: 'A guest account, or a passwordless account whose ' +
            'token is not from a sign-in in the last 5 minutes ' +
            '(fresh_login_required)',
        },
        404: { description: NOT_CONFIGURED },
        409: { description: 'Two-factor authentication is already enabled' },
        429: { description: 'Too many failed current_password proofs' },
      },
    }),
    noStore,
    requireAuth,
    throttleFailedPasswordProofs,
    validator('json', setupSchema),
    async (c) =>
      c.json(
        await c.var.totpService.startSetup(c.var.user.id, {
          currentPassword: c.req.valid('json').current_password,
          authTime: c.var.user.authTime,
        }),
        200,
      ),
  )
  .post(
    '/me/totp/confirm',
    describeRoute({
      tags: ['Users'],
      summary: 'Confirm two-factor setup with a first code',
      description: 'Turns two-factor authentication on and returns ten ' +
        'recovery codes. They are shown this once and never again.',
      security: [{ bearerAuth: [] }],
      responses: {
        200: { description: '{ recovery_codes: string[10] }' },
        400: { description: 'The code is not valid' },
        401: { description: 'Missing or invalid access token' },
        404: { description: `No setup in progress. Or: ${NOT_CONFIGURED}` },
        409: { description: 'Two-factor authentication is already enabled' },
      },
    }),
    noStore,
    requireAuth,
    validator('json', codeSchema),
    async (c) =>
      c.json(
        await c.var.totpService.confirm(
          c.var.user.id,
          c.req.valid('json').code,
        ),
        200,
      ),
  )
  .delete(
    '/me/totp',
    describeRoute({
      tags: ['Users'],
      summary: 'Turn two-factor authentication off',
      description: 'Needs a current code or an unused recovery code: an ' +
        'access token alone is not enough, since any app the user is signed ' +
        'into holds one.',
      security: [{ bearerAuth: [] }],
      responses: {
        204: {
          description:
            'Turned off; the secret and all recovery codes are deleted',
        },
        400: { description: 'Send exactly one of code or recovery_code' },
        401: {
          description: 'Missing or invalid access token, or a wrong proof',
        },
        404: { description: NOT_CONFIGURED },
        429: { description: 'Too many wrong proofs' },
      },
    }),
    requireAuth,
    throttleFailedTotpProofs,
    validator('json', disableSchema),
    async (c) => {
      const b = c.req.valid('json')
      await c.var.totpService.disable(
        c.var.user.id,
        (b.code ?? b.recovery_code)!,
      )
      return c.body(null, 204)
    },
  )
  .delete(
    '/:id/totp',
    describeRoute({
      tags: ['Users'],
      summary: "Reset a user's two-factor authentication (operator)",
      description: 'For a user who lost both their device and their ' +
        'recovery codes. They can then sign in with their password alone and ' +
        'set up two-factor authentication again.',
      security: [{ bearerAuth: [] }],
      parameters: [{
        name: 'id',
        in: 'path',
        required: true,
        description: 'User id',
        schema: { type: 'string', format: 'uuid' },
      }],
      responses: {
        204: { description: 'Reset (idempotent)' },
        401: { description: 'Missing or invalid access token' },
        403: { description: 'Missing users:update:any on a platform token' },
      },
    }),
    requireAuth,
    requirePermission('users:update:any'),
    async (c) => {
      await c.var.totpService.reset(c.req.param('id'))
      return c.body(null, 204)
    },
  )

export default totp
