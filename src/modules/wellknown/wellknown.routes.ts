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
      authorization_endpoint: `${iss}/authorize`,
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['password', 'refresh_token'],
    })
  })

export default wellknown
