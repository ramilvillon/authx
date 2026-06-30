export const PERMISSIONS = {
  USERS_LIST: 'users:list',
  USERS_READ_ANY: 'users:read:any',
  USERS_UPDATE_ANY: 'users:update:any',
  USERS_DELETE_ANY: 'users:delete:any',
} as const

export const ROLE_USER = 'user'
export const ROLE_ADMIN = 'admin'

export const ROLE_GRANTS: Record<string, string[]> = {
  [ROLE_ADMIN]: Object.values(PERMISSIONS),
  [ROLE_USER]: [],
}
