import { Hono } from 'hono'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { AppError } from '../../lib/errors.ts'
import {
  passwordResetRequestSchema,
  passwordResetSchema,
  resendSchema,
  verifyQuerySchema,
} from './verification.schema.ts'
import {
  verificationErrorPage,
  verificationSuccessPage,
} from './verification-page.ts'

const verification = new Hono<AppEnv>()
  // One redemption endpoint for every out-of-band confirmation; the token's
  // purpose decides what happens, so a link can only ever do the one thing it
  // was minted for.
  .get('/confirm', validator('query', verifyQuerySchema), async (c) => {
    try {
      await c.var.verificationService.confirm(c.req.valid('query').token)
    } catch (e) {
      // A taken address is neither invalid nor expired, and the link is still
      // good -- saying "request a new one" would send the owner to re-run a
      // flow that works.
      if (e instanceof AppError && e.code === 'email_taken') {
        return c.html(
          verificationErrorPage(
            'That address is already in use by another account. ' +
              'The link is still valid -- confirm again once it is free, ' +
              'or request the change to a different address.',
          ),
          409,
        )
      }
      return c.html(verificationErrorPage(), 400)
    }
    return c.html(verificationSuccessPage())
  })
  .get('/verify-email', validator('query', verifyQuerySchema), async (c) => {
    try {
      await c.var.verificationService.verifyEmail(c.req.valid('query').token)
    } catch {
      return c.html(verificationErrorPage(), 400)
    }
    return c.html(verificationSuccessPage())
  })
  // Separate from /confirm on purpose: a reset cannot act on a GET, because the
  // user still has to choose a new password. /confirm refuses these tokens.
  .post(
    '/password-reset/request',
    validator('json', passwordResetRequestSchema),
    async (c) => {
      // Best-effort + always 204: never reveal whether the address exists.
      await c.var.verificationService.startPasswordReset(
        c.req.valid('json').email,
      ).catch(() => {})
      return c.body(null, 204)
    },
  )
  .post(
    '/password-reset',
    validator('json', passwordResetSchema),
    async (c) => {
      const { token, password } = c.req.valid('json')
      await c.var.verificationService.resetPassword(token, password)
      return c.body(null, 204)
    },
  )
  .post('/verify-email/resend', validator('json', resendSchema), async (c) => {
    // Best-effort + always 204: never reveal whether the email exists/is verified.
    await c.var.verificationService.resend(c.req.valid('json').email).catch(
      () => {},
    )
    return c.body(null, 204)
  })

export default verification
