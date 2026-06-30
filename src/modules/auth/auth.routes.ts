import { Hono } from 'hono'
import { googleAuth } from '@hono/oauth-providers/google'
import { describeRoute } from 'hono-openapi'
import { resolver, validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import {
  revokeSchema,
  tokenPairSchema,
  tokenRequestSchema,
} from './auth.schema.ts'

const json = (schema: ReturnType<typeof resolver>) => ({
  'application/json': { schema },
})

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
        ? await svc.passwordGrant(body.username, body.password)
        : await svc.refreshGrant(body.refresh_token)
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
      const pair = await c.var.authService.loginWithGoogle({
        providerAccountId: profile.id,
        email: profile.email,
        emailVerified: profile.verified_email ?? false,
      })
      return c.json(pair, 200)
    },
  )

export default auth
