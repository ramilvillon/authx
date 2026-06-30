export type AuthenticatedUser = {
  id: string
  email: string
  permissions: string[]
  org: string
  aud: string
}
