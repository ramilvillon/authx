import { defineConfig } from 'drizzle-kit'
import { dbSsl } from './src/config.ts'

const host = Deno.env.get('DB_HOST') ?? 'localhost'
const mode = Deno.env.get('DB_SSL') || undefined
if (mode !== undefined && mode !== 'required' && mode !== 'off') {
  throw new Error('DB_SSL must be "required" or "off"')
}
const ssl = dbSsl(host, mode, Deno.env.get('DB_SSL_CA') ?? '')

export default defineConfig({
  dialect: 'mysql',
  schema: './src/db/schema.ts',
  out: './src/db/migrations',
  dbCredentials: {
    host,
    port: Number(Deno.env.get('DB_PORT') ?? 3306),
    user: Deno.env.get('DB_USER')!,
    password: Deno.env.get('DB_PASS') ?? '',
    database: Deno.env.get('DB_NAME')!,
    ...(ssl ? { ssl } : {}),
  },
})
