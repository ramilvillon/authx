import { assertEquals, assertThrows } from '@std/assert'
import { loadConfig } from '../../src/config.ts'

const base = {
  PORT: '3000',
  LOG_LEVEL: 'info',
  DB_HOST: 'localhost',
  DB_PORT: '3306',
  DB_USER: 'app',
  DB_PASS: 'app',
  DB_NAME: 'app',
  JWT_PRIVATE_KEY: 'pk',
  JWT_PUBLIC_KEY: 'pub',
  JWT_ISSUER: 'http://localhost:3000',
  ACCESS_TOKEN_TTL: '900',
  REFRESH_TOKEN_TTL: '2592000',
  GOOGLE_CLIENT_ID: 'gid',
  GOOGLE_CLIENT_SECRET: 'gsecret',
  GOOGLE_REDIRECT_URI: 'http://localhost:3000/oauth/google/callback',
  RATE_LIMIT_WINDOW_MS: '60000',
  RATE_LIMIT_MAX: '100',
}

Deno.test('loadConfig parses and coerces env', () => {
  const cfg = loadConfig(base)
  assertEquals(cfg.port, 3000)
  assertEquals(cfg.accessTokenTtl, 900)
  assertEquals(cfg.redisUrl, undefined)
  assertEquals(cfg.db, {
    host: 'localhost',
    port: 3306,
    user: 'app',
    password: 'app',
    name: 'app',
  })
})

Deno.test('loadConfig throws on missing DB_NAME', () => {
  const { DB_NAME: _omit, ...partial } = base
  assertThrows(() => loadConfig(partial), Error, 'DB_NAME')
})

Deno.test('loadConfig throws on missing required value', () => {
  const { JWT_PRIVATE_KEY: _omit, ...partial } = base
  assertThrows(() => loadConfig(partial), Error, 'JWT_PRIVATE_KEY')
})

Deno.test('loadConfig defaults SSO + auth-code TTLs', () => {
  const cfg = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: 'x',
    JWT_PUBLIC_KEY: 'y',
    JWT_ISSUER: 'http://t',
  })
  assertEquals(cfg.ssoSessionTtl, 2592000)
  assertEquals(cfg.authCodeTtl, 60)
})

Deno.test('loadConfig parses JWT_PREVIOUS_PUBLIC_KEYS (defaults to [])', () => {
  const base = {
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: 'x',
    JWT_PUBLIC_KEY: 'y',
    JWT_ISSUER: 'http://t',
  }
  assertEquals(loadConfig(base).jwtPreviousPublicKeys, [])
  assertEquals(
    loadConfig({ ...base, JWT_PREVIOUS_PUBLIC_KEYS: '["pemA","pemB"]' })
      .jwtPreviousPublicKeys,
    ['pemA', 'pemB'],
  )
})

Deno.test('loadConfig defaults EMAIL_VERIFICATION_TTL', () => {
  const cfg = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: 'x',
    JWT_PUBLIC_KEY: 'y',
    JWT_ISSUER: 'http://t',
  })
  assertEquals(cfg.emailVerificationTtl, 86400)
})
