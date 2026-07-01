import {
  boolean,
  datetime,
  index,
  mysqlTable,
  primaryKey,
  text,
  unique,
  varchar,
} from 'drizzle-orm/mysql-core'

export const users = mysqlTable('users', {
  id: varchar('id', { length: 36 }).primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }),
  emailVerified: boolean('email_verified').notNull().default(false),
  name: varchar('name', { length: 255 }),
  givenName: varchar('given_name', { length: 255 }),
  familyName: varchar('family_name', { length: 255 }),
  picture: varchar('picture', { length: 1024 }),
  createdAt: datetime('created_at').notNull(),
  updatedAt: datetime('updated_at').notNull(),
})

export const refreshTokens = mysqlTable('refresh_tokens', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
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
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
  name: varchar('name', { length: 64 }).notNull(),
}, (t) => ({ serviceName: unique().on(t.appServiceId, t.name) }))

export const permissions = mysqlTable('permissions', {
  id: varchar('id', { length: 36 }).primaryKey(),
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
  key: varchar('key', { length: 64 }).notNull(),
}, (t) => ({ serviceKey: unique().on(t.appServiceId, t.key) }))

export const rolePermissions = mysqlTable('role_permissions', {
  roleId: varchar('role_id', { length: 36 }).notNull(),
  permissionId: varchar('permission_id', { length: 36 }).notNull(),
}, (t) => ({ pk: primaryKey({ columns: [t.roleId, t.permissionId] }) }))

export const userRoles = mysqlTable('user_roles', {
  userId: varchar('user_id', { length: 36 }).notNull(),
  roleId: varchar('role_id', { length: 36 }).notNull(),
}, (t) => ({ pk: primaryKey({ columns: [t.userId, t.roleId] }) }))

export const clientRoles = mysqlTable('client_roles', {
  clientAppServiceId: varchar('client_app_service_id', { length: 36 })
    .notNull(),
  roleId: varchar('role_id', { length: 36 }).notNull(),
}, (t) => ({ pk: primaryKey({ columns: [t.clientAppServiceId, t.roleId] }) }))

export const organizations = mysqlTable('organizations', {
  id: varchar('id', { length: 36 }).primaryKey(),
  slug: varchar('slug', { length: 64 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  createdAt: datetime('created_at').notNull(),
})

export const appServices = mysqlTable('app_services', {
  id: varchar('id', { length: 36 }).primaryKey(),
  orgId: varchar('org_id', { length: 36 }).notNull(),
  clientId: varchar('client_id', { length: 64 }).notNull().unique(),
  clientSecretHash: varchar('client_secret_hash', { length: 255 }),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 64 }).notNull(),
  audience: varchar('audience', { length: 128 }).notNull().unique(),
  type: varchar('type', { length: 16 }).notNull(), // 'public' | 'confidential'
  redirectUris: text('redirect_uris').notNull().default('[]'), // JSON array
  createdAt: datetime('created_at').notNull(),
}, (t) => ({ orgIdx: index('app_services_org_idx').on(t.orgId) }))

export const memberships = mysqlTable('memberships', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  orgId: varchar('org_id', { length: 36 }).notNull(),
  createdAt: datetime('created_at').notNull(),
}, (t) => ({ userOrg: unique().on(t.userId, t.orgId) }))

export const sessions = mysqlTable('sessions', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  expiresAt: datetime('expires_at').notNull(),
  revokedAt: datetime('revoked_at'),
  createdAt: datetime('created_at').notNull(),
})

export const authorizationCodes = mysqlTable('authorization_codes', {
  id: varchar('id', { length: 36 }).primaryKey(),
  codeHash: varchar('code_hash', { length: 64 }).notNull().unique(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
  redirectUri: varchar('redirect_uri', { length: 2048 }).notNull(),
  codeChallenge: varchar('code_challenge', { length: 128 }).notNull(),
  codeChallengeMethod: varchar('code_challenge_method', { length: 8 })
    .notNull(),
  scope: text('scope').notNull(),
  nonce: varchar('nonce', { length: 255 }),
  authTime: datetime('auth_time').notNull(),
  expiresAt: datetime('expires_at').notNull(),
  consumedAt: datetime('consumed_at'),
  createdAt: datetime('created_at').notNull(),
})

export const emailVerificationTokens = mysqlTable('email_verification_tokens', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  email: varchar('email', { length: 255 }).notNull(),
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  expiresAt: datetime('expires_at').notNull(),
  consumedAt: datetime('consumed_at'),
  createdAt: datetime('created_at').notNull(),
})
