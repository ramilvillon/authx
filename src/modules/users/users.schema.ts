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
  // `picture` is served to relying parties as the OIDC `picture` claim, which
  // MUST refer to an image file — so the scheme is constrained here, at the
  // trust boundary. zod's .url() is a bare `new URL()` parse and accepts
  // `javascript:`/`data:` active-content URIs. URL.parse (not `new URL`) because
  // zod runs this refinement even when .url() already failed.
  picture: z.string().url().max(1024).refine(
    (v) => ['http:', 'https:'].includes(URL.parse(v)?.protocol ?? ''),
    { message: 'must be an http(s) URL' },
  ).optional(),
}).refine((v) => Object.values(v).some((x) => x !== undefined), {
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
