// TOTP (RFC 6238) and the pieces around it, on WebCrypto alone.
//
// SHA-1, 6 digits and a 30 s step are not a weakness here: they are what every
// authenticator app implements, and HMAC-SHA-1 is not affected by SHA-1's
// collision attacks. Anything else would work in some apps and not others.
import {
  decodeBase32,
  decodeBase64,
  encodeBase32,
  encodeBase64,
} from '@std/encoding'

export const STEP_SECONDS = 30

export function currentStep(nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000 / STEP_SECONDS)
}

// RFC 4226 section 5.3: HMAC the big-endian counter, dynamic truncation.
export async function hotp(
  secret: Uint8Array<ArrayBuffer>,
  counter: number,
  digits = 6,
): Promise<string> {
  const msg = new Uint8Array(8)
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter))
  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  )
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg))
  const off = mac[mac.length - 1] & 0x0f
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) |
    (mac[off + 2] << 8) | mac[off + 3]
  return String(bin % 10 ** digits).padStart(digits, '0')
}

// The step a code belongs to, within one step of clock drift either way, or
// null. Returning the step (not a boolean) is what lets the caller refuse a
// replay: it records the step and accepts only later ones.
export async function matchStep(
  secret: Uint8Array<ArrayBuffer>,
  code: string,
  step = currentStep(),
): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null
  for (const s of [step - 1, step, step + 1]) {
    if (timingSafeEqual(await hotp(secret, s), code)) return s
  }
  return null
}

export function generateSecret(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(20))
}

// Authenticator apps want base32 without the '=' padding.
export function toBase32(bytes: Uint8Array<ArrayBuffer>): string {
  return encodeBase32(bytes).replace(/=+$/, '')
}

export function fromBase32(s: string): Uint8Array<ArrayBuffer> {
  return decodeBase32(s.padEnd(Math.ceil(s.length / 8) * 8, '='))
}

export function importEncryptionKey(b64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    decodeBase64(b64),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  )
}

// `v1` names the key generation. Rotating TOTP_ENCRYPTION_KEY later means
// adding a v2 key and re-sealing lazily; no migration, because the version
// travels with every value.
export async function sealSecret(
  key: CryptoKey,
  secret: Uint8Array<ArrayBuffer>,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secret)
  return `v1:${encodeBase64(iv)}:${encodeBase64(new Uint8Array(ct))}`
}

// Throws on an unknown version and on any tampering (GCM authenticates both
// the ciphertext and, through the nonce, the IV).
export async function openSecret(
  key: CryptoKey,
  sealed: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const [version, iv, ct] = sealed.split(':')
  if (version !== 'v1' || !iv || !ct) throw new Error('unknown secret format')
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: decodeBase64(iv) },
      key,
      decodeBase64(ct),
    ),
  )
}

// 10 bytes = 80 bits = exactly 16 base32 characters. At 80 bits a plain
// SHA-256 at rest is enough: there is nothing to brute-force offline.
export function generateRecoveryCodes(n = 10): string[] {
  return Array.from(
    { length: n },
    () =>
      encodeBase32(crypto.getRandomValues(new Uint8Array(10)))
        .match(/.{4}/g)!
        .join('-'),
  )
}

// What a person types is not what we displayed: case, dashes and spaces vary.
export function normalizeRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, '')
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

// Key URI format (the de facto spec from Google Authenticator). The issuer is
// repeated as a parameter because some apps read only one of the two.
export function otpauthUri(
  issuerHost: string,
  account: string,
  secretB32: string,
): string {
  const label = encodeURIComponent(`${issuerHost}:${account}`)
  const q = new URLSearchParams({
    secret: secretB32,
    issuer: issuerHost,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  })
  return `otpauth://totp/${label}?${q}`
}
