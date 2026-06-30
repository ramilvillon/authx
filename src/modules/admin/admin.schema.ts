import { z } from 'zod'

export const createOrgSchema = z.object({
  slug: z.string().min(1).max(64),
  name: z.string().min(1).max(255),
})

export const registerServiceSchema = z.object({
  slug: z.string().min(1).max(64),
  name: z.string().min(1).max(255),
  audience: z.string().min(1).max(128),
  type: z.enum(['public', 'confidential']),
  redirectUris: z.array(z.string().url()).default([]),
})

export const addMemberSchema = z.object({ userId: z.string().min(1) })
export const createRoleSchema = z.object({ name: z.string().min(1).max(64) })
export const createPermissionSchema = z.object({
  key: z.string().min(1).max(64),
})
export const grantPermissionSchema = z.object({
  permissionId: z.string().min(1),
})
export const assignRoleSchema = z.object({ roleId: z.string().min(1) })
