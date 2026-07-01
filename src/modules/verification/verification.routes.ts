import { Hono } from 'hono'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { resendSchema, verifyQuerySchema } from './verification.schema.ts'
import {
  verificationErrorPage,
  verificationSuccessPage,
} from './verification-page.ts'

const verification = new Hono<AppEnv>()
  .get('/verify-email', validator('query', verifyQuerySchema), async (c) => {
    try {
      await c.var.verificationService.verifyEmail(c.req.valid('query').token)
    } catch {
      return c.html(verificationErrorPage(), 400)
    }
    return c.html(verificationSuccessPage())
  })
  .post('/verify-email/resend', validator('json', resendSchema), async (c) => {
    // Best-effort + always 204: never reveal whether the email exists/is verified.
    await c.var.verificationService.resend(c.req.valid('json').email).catch(
      () => {},
    )
    return c.body(null, 204)
  })

export default verification
