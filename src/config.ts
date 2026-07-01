import { z } from 'zod'

const schema = z.object({
  PORT: z.coerce.number().default(3000),
  LOG_LEVEL: z.string().default('info'),
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.coerce.number().default(3306),
  DB_USER: z.string().min(1),
  DB_PASS: z.string().default(''),
  DB_NAME: z.string().min(1),
  JWT_PRIVATE_KEY: z.string().min(1),
  JWT_PUBLIC_KEY: z.string().min(1),
  JWT_ISSUER: z.string().min(1),
  JWT_PREVIOUS_PUBLIC_KEYS: z.string().default('[]').transform((v, ctx) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(v)
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'JWT_PREVIOUS_PUBLIC_KEYS must be valid JSON',
      })
      return z.NEVER
    }
    if (!Array.isArray(parsed) || !parsed.every((x) => typeof x === 'string')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'JWT_PREVIOUS_PUBLIC_KEYS must be a JSON array of PEM strings',
      })
      return z.NEVER
    }
    return parsed as string[]
  }),
  ACCESS_TOKEN_TTL: z.coerce.number().default(900),
  REFRESH_TOKEN_TTL: z.coerce.number().default(2592000),
  SSO_SESSION_TTL: z.coerce.number().default(2592000),
  AUTH_CODE_TTL: z.coerce.number().default(60),
  GOOGLE_CLIENT_ID: z.string().default(''),
  GOOGLE_CLIENT_SECRET: z.string().default(''),
  GOOGLE_REDIRECT_URI: z.string().default(''),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60000),
  RATE_LIMIT_MAX: z.coerce.number().default(100),
  // Only trust X-Forwarded-For when the app sits behind a known reverse proxy.
  TRUST_PROXY: z.enum(['true', 'false']).default('false').transform((v) =>
    v === 'true'
  ),
  REDIS_URL: z.string().optional(),
})

export type Config = {
  port: number
  logLevel: string
  db: {
    host: string
    port: number
    user: string
    password: string
    name: string
  }
  jwtPrivateKey: string
  jwtPublicKey: string
  issuer: string
  jwtPreviousPublicKeys: string[]
  accessTokenTtl: number
  refreshTokenTtl: number
  ssoSessionTtl: number
  authCodeTtl: number
  google: { clientId: string; clientSecret: string; redirectUri: string }
  rateLimit: { windowMs: number; max: number }
  trustProxy: boolean
  redisUrl?: string
}

export function loadConfig(env: Record<string, string | undefined>): Config {
  const parsed = schema.safeParse(env)
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => i.path.join('.')).join(', ')
    throw new Error(`Invalid configuration: ${issues}`)
  }
  const e = parsed.data
  return {
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
    db: {
      host: e.DB_HOST,
      port: e.DB_PORT,
      user: e.DB_USER,
      password: e.DB_PASS,
      name: e.DB_NAME,
    },
    jwtPrivateKey: e.JWT_PRIVATE_KEY,
    jwtPublicKey: e.JWT_PUBLIC_KEY,
    issuer: e.JWT_ISSUER,
    jwtPreviousPublicKeys: e.JWT_PREVIOUS_PUBLIC_KEYS,
    accessTokenTtl: e.ACCESS_TOKEN_TTL,
    refreshTokenTtl: e.REFRESH_TOKEN_TTL,
    ssoSessionTtl: e.SSO_SESSION_TTL,
    authCodeTtl: e.AUTH_CODE_TTL,
    google: {
      clientId: e.GOOGLE_CLIENT_ID,
      clientSecret: e.GOOGLE_CLIENT_SECRET,
      redirectUri: e.GOOGLE_REDIRECT_URI,
    },
    rateLimit: { windowMs: e.RATE_LIMIT_WINDOW_MS, max: e.RATE_LIMIT_MAX },
    trustProxy: e.TRUST_PROXY,
    redisUrl: e.REDIS_URL,
  }
}
