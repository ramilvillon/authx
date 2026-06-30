import { createApp } from './app.ts'
import { createDeps } from './deps.ts'
import { createDb } from './db/client.ts'
import { loadConfig } from './config.ts'

const config = loadConfig(Deno.env.toObject())
const { db } = createDb(config)
const deps = createDeps(config, db)
const app = createApp(deps)

Deno.serve({ port: config.port }, app.fetch)
