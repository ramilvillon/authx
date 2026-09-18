import { Hono } from 'hono'
import { z } from 'zod'
import { describeRoute } from 'hono-openapi'
import { resolver, validator } from 'hono-openapi/zod'
import type { OpenAPIV3 } from 'openapi-types'
import type { AppEnv } from '../../deps.ts'
import {
  guestCredentialSchema,
  guestSchema,
  publicUserSchema,
  registerSchema,
  updateUserSchema,
} from './users.schema.ts'
import { createMiddleware } from 'hono/factory'
import { requireAuth } from '../../middleware/auth.ts'
import { makeRateLimiter } from '../../middleware/rate-limit.ts'
import {
  requirePermission,
  requireSelfOrPermission,
} from '../../middleware/authorize.ts'

const idParam: OpenAPIV3.ParameterObject = {
  name: 'id',
  in: 'path',
  required: true,
  description: 'User id',
  schema: { type: 'string', format: 'uuid' },
}

const json = (schema: ReturnType<typeof resolver>) => ({
  'application/json': { schema },
})

// Throttles wrong `current_password` guesses. Registered *after* requireAuth on
// purpose: clientKey falls back to the caller's IP when no user is set, so an
// earlier registration would let unauthenticated requests with a junk bearer
// token drain the bucket and lock the real owner out of their own password
// change. After requireAuth the key is the authenticated user id, so the budget
// belongs to the account being defended. Only a 401 counts, so ordinary profile
// updates and malformed bodies never spend it.
// ponytail: built per request because the store only exists on the context;
// the limiter is cheap to construct and all its state lives in the store.
const throttleFailedPasswordProofs = createMiddleware<AppEnv>((c, next) =>
  makeRateLimiter(c.var.rateStore, {
    windowMs: c.var.config.rateLimit.windowMs,
    limit: 5,
    prefix: 'password-proof',
    countOnly: (status) => status === 401,
  })(c, next)
)

const users = new Hono<AppEnv>()
  .post(
    '/',
    describeRoute({
      tags: ['Users'],
      summary: 'Register a new user',
      responses: {
        201: {
          description: 'Created',
          content: json(resolver(publicUserSchema)),
        },
        400: { description: 'Invalid input' },
        409: { description: 'Email already registered' },
      },
    }),
    validator('json', registerSchema),
    async (c) => {
      const user = await c.var.userService.register(c.req.valid('json'))
      // registerSchema requires an email, so this is always set here -- the
      // guard is a type fix (PublicUser.email is now nullable for guests
      // created elsewhere), not a reachable branch on this route.
      if (user.email) {
        try {
          await c.var.verificationService.startVerification(
            user.id,
            user.email,
          )
        } catch (err) {
          c.var.logger.warn({ err }, 'verification email failed to send')
        }
      }
      return c.json(user, 201)
    },
  )
  .post(
    '/guest',
    describeRoute({
      tags: ['Users'],
      summary: 'Create a guest account',
      description:
        'Creates an account with a generated username and password and no ' +
        "email address, and makes it a member of the client service's org. " +
        'The credentials are returned once and are not retrievable again; ' +
        'the client stores them and re-authenticates with grant_type=password.',
      responses: {
        201: {
          description: 'Created',
          content: json(resolver(guestCredentialSchema)),
        },
        400: { description: 'Invalid input' },
        404: { description: 'Guest accounts are not enabled for this client' },
        429: { description: 'Too many guest accounts from this address' },
      },
    }),
    // Unauthenticated and it creates a row, so it needs its own bucket. There
    // is no authenticated user here, so makeRateLimiter falls back to the
    // client address.
    // Brief's illustration named this field `limit`; the real config field is
    // `max` (see app.ts / config.ts), so that's what's read here.
    (c, next) =>
      makeRateLimiter(c.var.rateStore, {
        windowMs: c.var.config.rateLimit.windowMs,
        limit: c.var.config.rateLimit.max,
        prefix: 'guest',
      })(c, next),
    validator('json', guestSchema),
    async (c) => {
      const cred = await c.var.userService.createGuest(
        c.req.valid('json').client_id,
      )
      return c.json(cred, 201)
    },
  )
  .get(
    '/me',
    describeRoute({
      tags: ['Users'],
      summary: 'Get the authenticated user',
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'The current user',
          content: json(resolver(publicUserSchema)),
        },
        401: { description: 'Missing or invalid access token' },
      },
    }),
    requireAuth,
    (c) => c.json(c.var.user, 200),
  )
  .get(
    '/',
    describeRoute({
      tags: ['Users'],
      summary: 'List all users',
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: 'All users',
          content: json(resolver(z.array(publicUserSchema))),
        },
        401: { description: 'Missing or invalid access token' },
        403: { description: 'Missing the users:list permission' },
      },
    }),
    requireAuth,
    requirePermission('users:list'),
    async (c) => {
      return c.json(await c.var.userService.list(), 200)
    },
  )
  .get(
    '/:id',
    describeRoute({
      tags: ['Users'],
      summary: 'Get a user by id',
      security: [{ bearerAuth: [] }],
      parameters: [idParam],
      responses: {
        200: {
          description: 'The user',
          content: json(resolver(publicUserSchema)),
        },
        401: { description: 'Missing or invalid access token' },
        403: { description: 'Not the owner and missing users:read:any' },
        404: { description: 'User not found' },
      },
    }),
    requireAuth,
    requireSelfOrPermission('id', 'users:read:any'),
    async (c) => {
      return c.json(await c.var.userService.getById(c.req.param('id')), 200)
    },
  )
  .patch(
    '/:id',
    describeRoute({
      tags: ['Users'],
      summary: 'Update a user',
      security: [{ bearerAuth: [] }],
      parameters: [idParam],
      responses: {
        200: {
          description: 'The updated user',
          content: json(resolver(publicUserSchema)),
        },
        202: {
          description:
            'Applied, except a self-service email change, which is held until confirmed from the current address',
          content: json(resolver(publicUserSchema)),
        },
        400: {
          description:
            'Invalid input, or a self-service password change with no current_password',
        },
        401: {
          description:
            'Missing or invalid access token, or a wrong current_password',
        },
        403: { description: 'Not the owner and missing users:update:any' },
        404: { description: 'User not found' },
        429: { description: 'Too many failed current_password proofs' },
      },
    }),
    requireAuth,
    requireSelfOrPermission('id', 'users:update:any'),
    throttleFailedPasswordProofs,
    validator('json', updateUserSchema),
    async (c) => {
      const id = c.req.param('id')
      const isSelf = id === c.var.user.id
      const { email, ...rest } = c.req.valid('json')
      // A self-service email change is authorised out of band: the confirming
      // link goes to the account's CURRENT address, which the app service
      // holding this access token cannot read. Every other field applies now.
      // An operator on users:update:any is exempt, as with the password
      // challenge -- that path is already bound to the platform audience.
      const deferEmail = isSelf && email !== undefined
      const user = Object.keys(deferEmail ? rest : c.req.valid('json')).length
        ? await c.var.userService.update(
          id,
          deferEmail ? rest : c.req.valid('json'),
          {
            // Self-service is the only path where a password challenge is both
            // possible and meaningful; reaching someone else's record already
            // required users:update:any on a platform-audience token.
            requireCurrentPassword: isSelf,
          },
        )
        : await c.var.userService.getById(id)
      if (deferEmail) {
        await c.var.verificationService.startEmailChange(id, email!)
        return c.json(user, 202)
      }
      return c.json(user, 200)
    },
  )
  .delete(
    '/:id',
    describeRoute({
      tags: ['Users'],
      summary: 'Delete a user',
      security: [{ bearerAuth: [] }],
      parameters: [idParam],
      responses: {
        202: {
          description:
            'Self-service: a confirmation link was sent to the current address; the account is not deleted yet',
        },
        204: { description: 'Deleted (operator path)' },
        401: { description: 'Missing or invalid access token' },
        403: { description: 'Not the owner and missing users:delete:any' },
        404: { description: 'User not found' },
      },
    }),
    requireAuth,
    requireSelfOrPermission('id', 'users:delete:any'),
    async (c) => {
      const id = c.req.param('id')
      // Deleting your own account is authorised out of band, for the same
      // reason an email change is: the access token proves who you are, not
      // that you asked. An operator on users:delete:any is exempt.
      if (id === c.var.user.id) {
        await c.var.verificationService.startAccountDeletion(id)
        return c.json({ status: 'confirmation_sent' }, 202)
      }
      await c.var.userService.remove(id)
      return c.body(null, 204)
    },
  )

export default users
