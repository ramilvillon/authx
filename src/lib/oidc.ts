// Fields an OIDC claim set can be built from — a UserRecord is assignable.
export type OidcUser = {
  email: string
  emailVerified?: boolean
  name?: string | null
  givenName?: string | null
  familyName?: string | null
  picture?: string | null
  updatedAt: Date
}

const SUPPORTED_OIDC_SCOPES = ['openid', 'email', 'profile'] as const

// The supported OIDC scopes present in a space-separated request scope, in a
// stable canonical order.
export function grantedOidcScopes(requested: string): string[] {
  const req = new Set(requested.split(' ').filter(Boolean))
  return SUPPORTED_OIDC_SCOPES.filter((s) => req.has(s))
}

// Maps granted scopes to standard OIDC claims. `sub` is added by the caller.
// Null/absent profile fields are omitted rather than emitted as null.
export function claimsForScopes(
  user: OidcUser,
  scopes: string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  if (scopes.includes('email')) {
    out.email = user.email
    out.email_verified = user.emailVerified ?? false
  }
  if (scopes.includes('profile')) {
    if (user.name) out.name = user.name
    if (user.givenName) out.given_name = user.givenName
    if (user.familyName) out.family_name = user.familyName
    if (user.picture) out.picture = user.picture
    out.updated_at = Math.floor(user.updatedAt.getTime() / 1000)
  }
  return out
}
