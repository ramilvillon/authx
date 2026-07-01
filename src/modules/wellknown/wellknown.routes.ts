import { Hono } from 'hono'
import type { AppEnv } from '../../deps.ts'

const wellknown = new Hono<AppEnv>()
  .get('/jwks.json', (c) => c.json(c.var.keySet.jwks))
  .get('/openid-configuration', (c) => {
    const iss = c.var.config.issuer
    return c.json({
      issuer: iss,
      jwks_uri: `${iss}/.well-known/jwks.json`,
      token_endpoint: `${iss}/oauth/token`,
      authorization_endpoint: `${iss}/oauth/authorize`,
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: [
        'password',
        'refresh_token',
        'authorization_code',
        'client_credentials',
      ],
      userinfo_endpoint: `${iss}/oauth/userinfo`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid', 'email', 'profile'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'email',
        'email_verified',
        'name',
        'given_name',
        'family_name',
        'picture',
      ],
      token_endpoint_auth_methods_supported: ['client_secret_post'],
      code_challenge_methods_supported: ['S256'],
    })
  })

export default wellknown
