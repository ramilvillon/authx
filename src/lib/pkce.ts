import { encodeBase64Url } from '@std/encoding/base64url'

// PKCE S256: challenge = base64url(sha256(verifier)). Only S256 is supported.
export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  )
  return encodeBase64Url(new Uint8Array(digest))
}

export async function verifyChallenge(
  verifier: string,
  challenge: string,
): Promise<boolean> {
  return (await s256Challenge(verifier)) === challenge
}
