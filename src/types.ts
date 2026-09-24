export type AuthenticatedUser = {
  id: string
  email: string
  permissions: string[]
  org: string
  aud: string
  // Seconds; see AccessClaims.auth_time.
  authTime?: number
}
