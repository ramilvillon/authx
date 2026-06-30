import { z } from 'zod'

export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
  z.object({
    grant_type: z.literal('password'),
    username: z.string().email(),
    password: z.string().min(1),
    audience: z.string().min(1),
  }),
  z.object({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1),
  }),
  z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1),
    redirect_uri: z.string().min(1),
    code_verifier: z.string().min(1),
    client_id: z.string().min(1),
    client_secret: z.string().optional(),
  }),
])

export const revokeSchema = z.object({ refresh_token: z.string().min(1) })

export const tokenPairSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
})

export const authorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().default(''),
  state: z.string().optional(),
  code_challenge: z.string().min(1),
  code_challenge_method: z.literal('S256'),
})

export const authorizeFormSchema = authorizeQuerySchema.extend({
  email: z.string().email(),
  password: z.string().min(1),
})

export type TokenRequest = z.infer<typeof tokenRequestSchema>
export type TokenPair = z.infer<typeof tokenPairSchema>
