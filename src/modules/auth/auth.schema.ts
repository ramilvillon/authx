import { z } from 'zod'

export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
  z.object({
    grant_type: z.literal('password'),
    // Either an email or a generated guest username. NOT z.string().email():
    // that rejected every guest credential at the schema, before any lookup.
    username: z.string().min(1),
    password: z.string().min(1),
    audience: z.string().min(1),
  }),
  z.object({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1),
    // Required when the token belongs to a confidential client (or sent via
    // HTTP Basic instead); see authenticateTokenClient.
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
  }),
  z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1),
    redirect_uri: z.string().min(1),
    code_verifier: z.string().min(1),
    client_id: z.string().min(1),
    client_secret: z.string().optional(),
  }),
  z.object({
    grant_type: z.literal('client_credentials'),
    client_id: z.string().min(1),
    client_secret: z.string().min(1),
    audience: z.string().min(1),
  }),
])

export const revokeSchema = z.object({
  refresh_token: z.string().min(1),
  // As on the refresh grant: required for a confidential client's token.
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
})

// RFC 6749 section 5.2. Only the token endpoints speak this shape; the rest of
// the API keeps the catalogue's {error: {code, message}}.
export const oauthErrorSchema = z.object({
  error: z.enum([
    'invalid_request',
    'invalid_client',
    'invalid_grant',
    'unsupported_grant_type',
    'invalid_target',
  ]),
  error_description: z.string(),
})

export const tokenPairSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
  id_token: z.string().optional(),
})

export const authorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().default(''),
  state: z.string().optional(),
  nonce: z.string().optional(),
  code_challenge: z.string().min(1),
  code_challenge_method: z.literal('S256'),
})

export const authorizeFormSchema = authorizeQuerySchema.extend({
  email: z.string().email(),
  password: z.string().min(1),
  // Optional here on purpose: a missing token is a CSRF refusal (403), not a
  // malformed body (400). The handler decides.
  csrf_token: z.string().optional(),
})

export const clientCredentialsResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
})
export type ClientCredentialsResponse = z.infer<
  typeof clientCredentialsResponseSchema
>

export type TokenRequest = z.infer<typeof tokenRequestSchema>
export type TokenPair = z.infer<typeof tokenPairSchema>
