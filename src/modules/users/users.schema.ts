import { z } from 'zod'

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
})

export const updateUserSchema = z.object({
  email: z.string().email().optional(),
  password: z.string().min(8).optional(),
  name: z.string().max(255).optional(),
  given_name: z.string().max(255).optional(),
  family_name: z.string().max(255).optional(),
  picture: z.string().url().max(1024).optional(),
  email_verified: z.boolean().optional(),
}).refine((v) => Object.keys(v).length > 0, {
  message: 'at least one field is required',
})

export const publicUserSchema = z.object({
  id: z.string(),
  email: z.string(),
  createdAt: z.date(),
})

export type RegisterInput = z.infer<typeof registerSchema>
export type UpdateUserInput = z.infer<typeof updateUserSchema>
export type PublicUser = z.infer<typeof publicUserSchema>
