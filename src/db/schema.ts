import {
  datetime,
  mysqlTable,
  primaryKey,
  unique,
  varchar,
} from 'drizzle-orm/mysql-core'

export const users = mysqlTable('users', {
  id: varchar('id', { length: 36 }).primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }),
  createdAt: datetime('created_at').notNull(),
  updatedAt: datetime('updated_at').notNull(),
})

export const refreshTokens = mysqlTable('refresh_tokens', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  expiresAt: datetime('expires_at').notNull(),
  revokedAt: datetime('revoked_at'),
  replacedBy: varchar('replaced_by', { length: 36 }),
  createdAt: datetime('created_at').notNull(),
})

export const socialAccounts = mysqlTable('social_accounts', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  provider: varchar('provider', { length: 32 }).notNull(),
  providerAccountId: varchar('provider_account_id', { length: 255 }).notNull(),
  createdAt: datetime('created_at').notNull(),
}, (t) => ({
  providerAccount: unique().on(t.provider, t.providerAccountId),
}))

export const roles = mysqlTable('roles', {
  id: varchar('id', { length: 36 }).primaryKey(),
  name: varchar('name', { length: 64 }).notNull().unique(),
})

export const permissions = mysqlTable('permissions', {
  id: varchar('id', { length: 36 }).primaryKey(),
  key: varchar('key', { length: 64 }).notNull().unique(),
})

export const rolePermissions = mysqlTable('role_permissions', {
  roleId: varchar('role_id', { length: 36 }).notNull(),
  permissionId: varchar('permission_id', { length: 36 }).notNull(),
}, (t) => ({ pk: primaryKey({ columns: [t.roleId, t.permissionId] }) }))

export const userRoles = mysqlTable('user_roles', {
  userId: varchar('user_id', { length: 36 }).notNull(),
  roleId: varchar('role_id', { length: 36 }).notNull(),
}, (t) => ({ pk: primaryKey({ columns: [t.userId, t.roleId] }) }))
