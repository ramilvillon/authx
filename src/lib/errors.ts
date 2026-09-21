import type { ContentfulStatusCode } from 'hono/utils/http-status'

// The registry key is the wire `error.code`. One entry per distinct error.
export const ERRORS = {
  invalid_grant: { status: 400, message: 'invalid grant' },
  invalid_client: { status: 401, message: 'client authentication failed' },
  invalid_request: { status: 400, message: 'invalid request' },
  unsupported_grant_type: { status: 400, message: 'unsupported grant type' },
  invalid_token: { status: 401, message: 'invalid token' },
  missing_bearer_token: { status: 401, message: 'missing bearer token' },
  invalid_credentials: { status: 401, message: 'invalid credentials' },
  current_password_required: {
    status: 400,
    message: 'current_password is required to change a password',
  },
  invalid_refresh_token: { status: 401, message: 'invalid refresh token' },
  refresh_token_reuse: { status: 401, message: 'refresh token reuse detected' },
  unknown_client_id: { status: 400, message: 'unknown client_id' },
  unknown_audience: { status: 400, message: 'unknown audience' },
  redirect_uri_not_allowed: {
    status: 400,
    message: 'redirect_uri not allowed',
  },
  code_challenge_required: {
    status: 400,
    message: 'code_challenge with S256 is required',
  },
  unsupported_code_challenge_method: {
    status: 400,
    message: 'unsupported code_challenge_method',
  },
  invalid_verification_link: {
    status: 400,
    message: 'invalid verification link',
  },
  verification_link_expired: {
    status: 400,
    message: 'verification link expired',
  },
  account_has_no_email: {
    status: 400,
    message: 'this account has no email address',
  },
  user_not_found: { status: 404, message: 'user not found' },
  org_not_found: { status: 404, message: 'organization not found' },
  service_not_found: { status: 404, message: 'service not found' },
  email_taken: { status: 409, message: 'email already registered' },
  social_account_already_linked: {
    status: 409,
    message: 'that account is already linked to a different user',
  },
  org_slug_taken: {
    status: 409,
    message: 'an org with this slug already exists',
  },
  service_audience_taken: {
    status: 409,
    message: 'a service with this audience already exists',
  },
  role_name_taken: {
    status: 409,
    message: 'a role with this name already exists in this service',
  },
  permission_key_taken: {
    status: 409,
    message: 'a permission with this key already exists in this service',
  },
  not_org_member: { status: 403, message: 'not a member of this organization' },
  platform_required: { status: 403, message: 'platform token required' },
  google_email_unverified: {
    status: 403,
    message: 'google account email is not verified',
  },
  account_exists_link_password: {
    status: 403,
    message:
      'an account with this email already exists; sign in with your password to link Google',
  },
  google_login_disabled: {
    status: 404,
    message: 'google login is not configured',
  },
  // 404, matching google_login_disabled: a capability the deployment has not
  // enabled should not be distinguishable from one that does not exist.
  guest_accounts_disabled: {
    status: 404,
    message: 'guest accounts are not enabled for this client',
  },
  authorize_request_expired: {
    status: 400,
    message:
      'no sign-in in progress; start again from the application (GET /oauth/authorize)',
  },
  csrf_token_invalid: {
    status: 403,
    message:
      'csrf token missing or does not match; GET /oauth/authorize first and submit the csrf_token it renders along with its cookie',
  },
  forbidden: { status: 403, message: 'forbidden' },
} as const

export type ErrorCode = keyof typeof ERRORS

export class AppError extends Error {
  readonly status: ContentfulStatusCode
  readonly code: ErrorCode

  private constructor(code: ErrorCode, message: string) {
    super(message)
    this.name = 'AppError'
    this.code = code
    this.status = ERRORS[code].status as ContentfulStatusCode
  }

  static of(code: ErrorCode, message?: string): AppError {
    return new AppError(code, message ?? ERRORS[code].message)
  }
}
