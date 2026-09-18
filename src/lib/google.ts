import { decodeBase64Url } from '@std/encoding/base64url'
import { AppError } from './errors.ts'

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
  try {
    return JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)))
  } catch {
    throw AppError.of('invalid_grant')
  }
}

// Redeems a one-time server auth code from a native Google SDK.
export async function exchangeGoogleAuthCode(
  code: string,
  cfg: { clientId: string; clientSecret: string; redirectUri: string },
): Promise<GoogleIdentity> {
  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      redirect_uri: cfg.redirectUri,
      grant_type: 'authorization_code',
    }),
  })
  if (!res.ok) throw AppError.of('invalid_grant')
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
