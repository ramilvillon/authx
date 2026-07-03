import type { ContentfulStatusCode } from 'hono/utils/http-status'

// The registry key is the wire `error.code`. One entry per distinct error.
export const ERRORS = {
  invalid_grant: { status: 400, message: 'invalid grant' },
  invalid_client: { status: 401, message: 'client authentication failed' },
  invalid_request: { status: 400, message: 'invalid request' },
  invalid_token: { status: 401, message: 'invalid token' },
  missing_bearer_token: { status: 401, message: 'missing bearer token' },
  invalid_credentials: { status: 401, message: 'invalid credentials' },
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
  user_not_found: { status: 404, message: 'user not found' },
  org_not_found: { status: 404, message: 'organization not found' },
  service_not_found: { status: 404, message: 'service not found' },
  email_taken: { status: 409, message: 'email already registered' },
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
