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
  EMAIL_VERIFICATION_TTL: z.coerce.number().default(86400),
  // Local development only: logs the verification link (a live token) and the
  // recipient address in plaintext.
  // SMTP_HOST is the switch: set it and deps.ts wires the real sender, leave
  // it empty and the log sender stays. No separate on/off flag to fall out of
  // step with the settings it guards.
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_USER: z.string().default(''),
  SMTP_PASS: z.string().default(''),
  // Implicit TLS on connect (port 465). Port 587 starts plaintext and upgrades
  // with STARTTLS, which nodemailer does on its own.
  SMTP_SECURE: z.enum(['true', 'false']).default('false').transform((v) =>
    v === 'true'
  ),
  EMAIL_FROM: z.string().default(''),
  EMAIL_LOG_LINKS: z.enum(['true', 'false']).default('false').transform((v) =>
    v === 'true'
  ),
  GOOGLE_CLIENT_ID: z.string().default(''),
  GOOGLE_CLIENT_SECRET: z.string().default(''),
  GOOGLE_REDIRECT_URI: z.string().default(''),
  // The redirect_uri sent when redeeming a server auth code at
  // POST /users/me/social-links. Which value is correct depends on how the
  // client obtained the code, and there are three answers:
  //
  //   unset/empty  -> the parameter is OMITTED. An Android/iOS SDK server auth
  //                   code is not issued against a redirect URI, and RFC 6749
  //                   4.1.3 sends the parameter only if the authorization
  //                   request carried one. This is the default and the case
  //                   the endpoint was built for.
  //   postmessage  -> a web/JS client using Google's popup code flow.
  //   <a URL>      -> a client that did carry a redirect URI on the
  //                   authorization request; it must match exactly.
  //
  // The default (omit) was verified against live Google on 2026-09-21 with a
  // real iOS SDK code. The other two answers have not been, and no test can
  // stand in for Google accepting or rejecting the exchange -- so this stays
  // configuration rather than a constant, and getting it wrong is a config
  // change, not a code change and a deploy. See GOOGLE_REDIRECT_URI for the separate
  // browser-redirect leg, which is unrelated to this one.
  // ponytail: unset and empty both mean "omit". If a client ever needs a
  // literal empty redirect_uri on the wire, that is a fourth state and wants a
  // sentinel value rather than another variable.
  GOOGLE_BIND_REDIRECT_URI: z.string().default(''),
  // How long a row is kept AFTER it expires. This is the window in which a
  // replayed refresh token or authorization code is still recognised as a
  // replay rather than an unknown value, so it is a security setting, not
  // housekeeping. Defaults to 30 days.
  PRUNE_RETENTION: z.coerce.number().default(2592000),
  // How long a deleted account stays recoverable before `db:prune` erases it
  // and cascades. Account deletion is something an attacker can trigger, so
  // this is the window in which that is reversible. Defaults to 30 days.
  ACCOUNT_PURGE_GRACE: z.coerce.number().default(2592000),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60000),
  RATE_LIMIT_MAX: z.coerce.number().default(100),
  // Guest creation gets its own budget, tighter than the global default and
  // tunable independently of it: it is keyed on IP (no authenticated user
  // exists yet), and a mobile game behind carrier-grade NAT can have many
  // legitimate players sharing one address.
  GUEST_RATE_LIMIT: z.coerce.number().default(10),
  // Number of reverse proxies in front of this service. 0 means never trust
  // X-Forwarded-For. The count matters: proxies *append* to the header, so the
  // client-supplied prefix is only skipped when the hop count is exact.
  // Legacy `false`/`true` map to 0/1; `true` also warns at startup (main.ts).
  TRUST_PROXY: z.string().default('0').transform((v, ctx) => {
    if (v === 'false') return 0
    if (v === 'true') return 1
    const hops = Number(v)
    if (!Number.isInteger(hops) || hops < 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'TRUST_PROXY must be a non-negative integer (number of trusted proxy hops)',
      })
      return z.NEVER
    }
    return hops
  }),
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
  emailVerificationTtl: number
  emailLogLinks: boolean
  smtp: {
    host: string
    port: number
    user: string
    pass: string
    secure: boolean
    from: string
  }
  google: {
    clientId: string
    clientSecret: string
    redirectUri: string
    // Empty means: send no redirect_uri on the bind exchange.
    bindRedirectUri: string
  }
  pruneRetention: number
  accountPurgeGrace: number
  rateLimit: { windowMs: number; max: number; guestMax: number }
  trustProxyHops: number
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
    emailVerificationTtl: e.EMAIL_VERIFICATION_TTL,
    emailLogLinks: e.EMAIL_LOG_LINKS,
    smtp: {
      host: e.SMTP_HOST,
      port: e.SMTP_PORT,
      user: e.SMTP_USER,
      pass: e.SMTP_PASS,
      secure: e.SMTP_SECURE,
      from: e.EMAIL_FROM,
    },
    google: {
      clientId: e.GOOGLE_CLIENT_ID,
      clientSecret: e.GOOGLE_CLIENT_SECRET,
      redirectUri: e.GOOGLE_REDIRECT_URI,
      bindRedirectUri: e.GOOGLE_BIND_REDIRECT_URI,
    },
    pruneRetention: e.PRUNE_RETENTION,
    accountPurgeGrace: e.ACCOUNT_PURGE_GRACE,
    rateLimit: {
      windowMs: e.RATE_LIMIT_WINDOW_MS,
      max: e.RATE_LIMIT_MAX,
      guestMax: e.GUEST_RATE_LIMIT,
    },
    trustProxyHops: e.TRUST_PROXY,
  }
}

// The `state` cookie that guards the Google callback against CSRF is set with
// `Secure` by @hono/oauth-providers, and browsers drop a Secure cookie on a
// non-secure origin — except localhost and 127.0.0.1, which count as
// trustworthy. On any other plain-http host the cookie never comes back, and
// every callback 401s with nothing in the logs pointing at the cause. (Google
// itself also refuses to register a non-localhost http redirect URI, so this
// config cannot work against real Google either.) Returns the warning text, or
// null when the redirect URI is fine or unset.
export function insecureGoogleRedirectWarning(
  redirectUri: string,
): string | null {
  if (!redirectUri) return null
  let url: URL
  try {
    url = new URL(redirectUri)
  } catch {
    return `GOOGLE_REDIRECT_URI is not a valid URL: ${redirectUri}`
  }
  if (url.protocol !== 'http:') return null
  if (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) return null
  return `GOOGLE_REDIRECT_URI is plain http on a non-localhost host (${url.host}), ` +
    'so the browser will drop the Secure `state` cookie and every Google ' +
    'callback will fail with 401. Serve this over https (Google requires it ' +
    'for non-localhost redirect URIs anyway).'
}
