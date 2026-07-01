import { decodeBase64, encodeBase64 } from '@std/encoding/base64'
import { encodeBase64Url } from '@std/encoding/base64url'

// ponytail: JsonWebKey in TS 5.9/Deno 2.7 omits `kid`; widen to carry it through.
export type Jwk = JsonWebKey & { kid: string }

export type KeySet = {
  privateKeyPem: string
  publicKeyPem: string
  kid: string
  jwks: { keys: Jwk[] }
  byKid: Map<string, string>
}

const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const

function toPem(der: ArrayBuffer, label: string): string {
  const b64 = encodeBase64(new Uint8Array(der))
  const lines = b64.match(/.{1,64}/g)?.join('\n') ?? b64
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`
}

function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '')
  return new Uint8Array(decodeBase64(b64))
}

export async function generateRsaKeyPairPem(): Promise<
  { privateKeyPem: string; publicKeyPem: string }
> {
  const kp = await crypto.subtle.generateKey(
    { ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['sign', 'verify'],
  )
  const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey)
  const pub = await crypto.subtle.exportKey('spki', kp.publicKey)
  return {
    privateKeyPem: toPem(priv, 'PRIVATE KEY'),
    publicKeyPem: toPem(pub, 'PUBLIC KEY'),
  }
}

// RFC 7638 JWK thumbprint: deterministic id tied to the key material, so the
// kid in token headers always matches the published JWKS without manual config.
async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const json = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new Uint8Array(new TextEncoder().encode(json)),
  )
  return encodeBase64Url(new Uint8Array(digest))
}

async function publicPemToJwk(publicKeyPem: string): Promise<Jwk> {
  const pub = await crypto.subtle.importKey(
    'spki',
    pemToDer(publicKeyPem),
    RSA,
    true,
    ['verify'],
  )
  const jwk = await crypto.subtle.exportKey('jwk', pub)
  const kid = await thumbprint(jwk)
  return { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', use: 'sig', kid }
}

// Import the active private key and re-export it as a JWK carrying alg + kid, so
// hono/jwt emits a `kid` header when signing (it reads kid off a JWK signing key).
export async function privatePemToSigningJwk(
  privateKeyPem: string,
  kid: string,
): Promise<Jwk> {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToDer(privateKeyPem),
    RSA,
    true,
    ['sign'],
  )
  const jwk = await crypto.subtle.exportKey('jwk', key)
  return { ...jwk, alg: 'RS256', kid } as Jwk
}

export async function loadKeyRing(
  activePrivatePem: string,
  activePublicPem: string,
  previousPublicPems: string[] = [],
): Promise<KeySet> {
  const activeJwk = await publicPemToJwk(activePublicPem)
  const previousJwks = await Promise.all(previousPublicPems.map(publicPemToJwk))
  const byKid = new Map<string, string>()
  byKid.set(activeJwk.kid, activePublicPem)
  previousPublicPems.forEach((pem, i) => byKid.set(previousJwks[i].kid, pem))
  return {
    privateKeyPem: activePrivatePem,
    publicKeyPem: activePublicPem,
    kid: activeJwk.kid,
    jwks: { keys: [activeJwk, ...previousJwks] },
    byKid,
  }
}
