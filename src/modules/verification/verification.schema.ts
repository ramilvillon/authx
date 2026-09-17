import { z } from 'zod'

export const verifyQuerySchema = z.object({ token: z.string().min(1) })
export const resendSchema = z.object({ email: z.string().email() })

export const passwordResetRequestSchema = z.object({
  email: z.string().email(),
})
export const passwordResetSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8),
})
