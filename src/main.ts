import { createApp } from './app.ts'
import { createDeps } from './deps.ts'
import { createDb } from './db/client.ts'
import { loadConfig } from './config.ts'
import { createLogger } from './lib/logger.ts'

const config = loadConfig(Deno.env.toObject())

// `TRUST_PROXY` used to be a boolean; it is now the number of proxies in front
// of this service, because client-IP resolution has to skip exactly the hops
// our own proxies appended. `true` is still accepted but can only be guessed
// as 1, which under-counts a two-proxy topology (e.g. Cloudflare -> nginx) and
// would collapse every client into one shared rate-limit bucket.
if (Deno.env.get('TRUST_PROXY') === 'true') {
  createLogger(config).warn(
    'TRUST_PROXY=true is deprecated and is being read as 1 trusted proxy hop. ' +
      'Set TRUST_PROXY to the exact number of reverse proxies in front of this ' +
      'service (e.g. TRUST_PROXY=2 behind Cloudflare -> nginx). Too low a count ' +
      'shares one rate-limit bucket across all clients; too high a count lets ' +
      'clients spoof their own bucket via X-Forwarded-For.',
  )
}

const { db } = createDb(config)
const deps = await createDeps(config, db)
const app = createApp(deps)

Deno.serve({ port: config.port }, app.fetch)
