import { z } from 'zod'

export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
  z.object({
    grant_type: z.literal('password'),
    username: z.string().email(),
    password: z.string().min(1),
  }),
  z.object({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1),
  }),
])

export const revokeSchema = z.object({ refresh_token: z.string().min(1) })

export const tokenPairSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
})

export type TokenRequest = z.infer<typeof tokenRequestSchema>
export type TokenPair = z.infer<typeof tokenPairSchema>
