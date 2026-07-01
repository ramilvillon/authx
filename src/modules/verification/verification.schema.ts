import { z } from 'zod'

export const verifyQuerySchema = z.object({ token: z.string().min(1) })
export const resendSchema = z.object({ email: z.string().email() })
