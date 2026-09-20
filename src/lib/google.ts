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

// Redeems a one-time server auth code from a native Google SDK.
//
// `redirectUri` is empty by default, and empty means the parameter is OMITTED:
// a native SDK's server auth code is never issued against a redirect URI, and
// RFC 6749 4.1.3 sends the parameter only if one was present on the
// authorization request. A web/JS client using Google's popup flow needs
// 'postmessage' instead, and a client that did carry a redirect URI needs that
// exact URI -- so this is a caller's decision, taken from configuration
// (GOOGLE_BIND_REDIRECT_URI), not a constant this function picks.
//
// Nothing here can prove which value is right: only Google accepts or rejects
// the exchange, and the test stub asserts what we send, never what Google
// makes of it. Keeping it configurable is what makes a wrong answer a config
// change instead of a code change.
export async function exchangeGoogleAuthCode(
  code: string,
  cfg: { clientId: string; clientSecret: string; redirectUri?: string },
  logger: Logger,
): Promise<GoogleIdentity> {
  const form = new URLSearchParams({
    code,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    grant_type: 'authorization_code',
  })
  // Appended only when set, so the default stays a body with no redirect_uri
  // at all rather than an empty one -- those are different requests to Google.
  if (cfg.redirectUri) form.set('redirect_uri', cfg.redirectUri)
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
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
