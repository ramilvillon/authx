import { z } from 'zod'

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
})

export const updateUserSchema = z.object({
  email: z.string().email().optional(),
  password: z.string().min(8).optional(),
}).refine((v) => v.email !== undefined || v.password !== undefined, {
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
