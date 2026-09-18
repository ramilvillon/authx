import { decodeBase64Url } from '@std/encoding/base64url'
import { AppError } from './errors.ts'
import type { Logger } from './logger.ts'

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'

export type GoogleIdentity = {
  sub: string
  email: string
  emailVerified: boolean
}

// The id_token is DECODED, not signature-verified, and that is deliberate: it
// arrives over TLS in the response to our own client-authenticated POST, so
// the channel already proves it came from Google. Verifying it would need a
// JWKS fetch, a cache and key rotation — none of which this repo has, and no
// `jose` dependency. A token handed over by a *client* would be a different
// question entirely.
function decodeIdToken(idToken: string): Record<string, unknown> {
  const payload = idToken.split('.')[1]
  if (!payload) throw AppError.of('invalid_grant')
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)))
  } catch {
    throw AppError.of('invalid_grant')
  }
  // A payload that parses to null or a scalar (valid JSON, wrong shape) would
  // otherwise make `claims.sub` throw a raw TypeError below instead of the
  // usual invalid_grant.
  if (typeof parsed !== 'object' || parsed === null) {
    throw AppError.of('invalid_grant')
  }
  return parsed as Record<string, unknown>
}

// Redeems a one-time server auth code from a native Google SDK. There is
// deliberately no redirect_uri in this exchange: a native SDK's server auth
// code is never issued against one (RFC 6749 §4.1.3 sends the parameter only
// if one was present on the authorization request). A web/JS client using
// Google's `postmessage` flow instead would need redirect_uri: 'postmessage'
// -- a different code shape from this one, and not something this function
// should guess at.
export async function exchangeGoogleAuthCode(
  code: string,
  cfg: { clientId: string; clientSecret: string },
  logger: Logger,
): Promise<GoogleIdentity> {
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      grant_type: 'authorization_code',
    }),
    // A hung Google should not hold this request open indefinitely; app.ts's
    // request-level timeout(15000) only releases the client, not this fetch.
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) {
    // Google's error/error_description is what makes a redirect_uri_mismatch
    // (or any other exchange failure) diagnosable. Server log only -- never
    // in the client-facing AppError, which stays the generic invalid_grant.
    const detail = await res.text()
    logger.error(
      { status: res.status, detail },
      'Google token exchange failed',
    )
    throw AppError.of('invalid_grant')
  }
  const body = await res.json() as { id_token?: string }
  if (!body.id_token) throw AppError.of('invalid_grant')
  const claims = decodeIdToken(body.id_token)
  const sub = claims.sub
  const email = claims.email
  if (typeof sub !== 'string' || typeof email !== 'string') {
    throw AppError.of('invalid_grant')
  }
  return { sub, email, emailVerified: claims.email_verified === true }
}
