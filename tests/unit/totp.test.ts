import { assert, assertEquals, assertMatch, assertRejects } from '@std/assert'
import {
  currentStep,
  fromBase32,
  generateRecoveryCodes,
  generateSecret,
  hotp,
  importEncryptionKey,
  matchStep,
  normalizeRecoveryCode,
  openSecret,
  otpauthUri,
  sealSecret,
  timingSafeEqual,
  toBase32,
} from '../../src/lib/totp.ts'
import { encodeBase64 } from '@std/encoding'

// RFC 6238 Appendix B, SHA-1 rows. The seed is the ASCII string itself.
const RFC_SEED = new TextEncoder().encode('12345678901234567890')
const RFC_VECTORS: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
]

Deno.test('hotp matches the RFC 6238 SHA-1 vectors (8 digits)', async () => {
  for (const [t, expected] of RFC_VECTORS) {
    assertEquals(
      await hotp(RFC_SEED, Math.floor(t / 30), 8),
      expected,
      `T=${t}`,
    )
  }
})

Deno.test('hotp defaults to 6 digits: the last six of the 8-digit value', async () => {
  assertEquals(await hotp(RFC_SEED, 1), '287082')
})

Deno.test('matchStep accepts steps -1, 0 and +1 and returns the matched step', async () => {
  const step = 1000
  for (const s of [step - 1, step, step + 1]) {
    assertEquals(await matchStep(RFC_SEED, await hotp(RFC_SEED, s), step), s)
  }
})

Deno.test('matchStep refuses steps -2 and +2', async () => {
  const step = 1000
  for (const s of [step - 2, step + 2]) {
    assertEquals(await matchStep(RFC_SEED, await hotp(RFC_SEED, s), step), null)
  }
})

Deno.test('matchStep refuses anything that is not exactly six digits', async () => {
  const code = await hotp(RFC_SEED, 1000)
  for (const bad of ['', '12345', '1234567', `${code} `, 'abcdef']) {
    assertEquals(
      await matchStep(RFC_SEED, bad, 1000),
      null,
      JSON.stringify(bad),
    )
  }
})

Deno.test('currentStep is the 30 s window of the given time', () => {
  assertEquals(currentStep(59_000), 1)
  assertEquals(currentStep(60_000), 2)
})

Deno.test('generateSecret is 20 random bytes and round-trips through base32', () => {
  const s = generateSecret()
  assertEquals(s.length, 20)
  const b32 = toBase32(s)
  assertMatch(b32, /^[A-Z2-7]{32}$/) // 20 bytes = 32 chars, no padding
  assertEquals(fromBase32(b32), s)
  assert(toBase32(generateSecret()) !== b32)
})

const KEY_B64 = encodeBase64(new Uint8Array(32).fill(9))

Deno.test('sealSecret/openSecret round-trip, with a fresh IV each time', async () => {
  const key = await importEncryptionKey(KEY_B64)
  const secret = generateSecret()
  const a = await sealSecret(key, secret)
  const b = await sealSecret(key, secret)
  assertMatch(a, /^v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/)
  assert(a !== b, 'same secret must not seal to the same string')
  assertEquals(await openSecret(key, a), secret)
})

Deno.test('openSecret refuses a tampered ciphertext, a tampered IV and an unknown version', async () => {
  const key = await importEncryptionKey(KEY_B64)
  const sealed = await sealSecret(key, generateSecret())
  const [v, iv, ct] = sealed.split(':')
  const flip = (b64: string) => (b64[0] === 'A' ? 'B' : 'A') + b64.slice(1)
  await assertRejects(() => openSecret(key, `${v}:${iv}:${flip(ct)}`))
  await assertRejects(() => openSecret(key, `${v}:${flip(iv)}:${ct}`))
  await assertRejects(() => openSecret(key, `v2:${iv}:${ct}`))
})

Deno.test('openSecret refuses a value sealed under another key', async () => {
  const key = await importEncryptionKey(KEY_B64)
  const other = await importEncryptionKey(
    encodeBase64(new Uint8Array(32).fill(1)),
  )
  await assertRejects(async () =>
    openSecret(other, await sealSecret(key, generateSecret()))
  )
})

Deno.test('generateRecoveryCodes: ten distinct XXXX-XXXX-XXXX-XXXX base32 codes', () => {
  const codes = generateRecoveryCodes()
  assertEquals(codes.length, 10)
  assertEquals(new Set(codes).size, 10)
  for (const c of codes) assertMatch(c, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/)
})

Deno.test('normalizeRecoveryCode ignores case, dashes and whitespace', () => {
  assertEquals(
    normalizeRecoveryCode(' abcd-efgh ijkl-MNOP\n'),
    'ABCDEFGHIJKLMNOP',
  )
})

Deno.test('timingSafeEqual', () => {
  assert(timingSafeEqual('123456', '123456'))
  assert(!timingSafeEqual('123456', '123457'))
  assert(!timingSafeEqual('123456', '12345'))
})

Deno.test('otpauthUri carries the parameters every authenticator app reads', () => {
  const uri = new URL(otpauthUri('auth.example.com', 'a@b.com', 'JBSWY3DP'))
  assertEquals(uri.protocol, 'otpauth:')
  assertEquals(
    decodeURIComponent(uri.pathname),
    '//totp/auth.example.com:a@b.com',
  )
  assertEquals(uri.searchParams.get('secret'), 'JBSWY3DP')
  assertEquals(uri.searchParams.get('issuer'), 'auth.example.com')
  assertEquals(uri.searchParams.get('algorithm'), 'SHA1')
  assertEquals(uri.searchParams.get('digits'), '6')
  assertEquals(uri.searchParams.get('period'), '30')
})
