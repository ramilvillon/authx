import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'mysql',
  schema: './src/db/schema.ts',
  out: './src/db/migrations',
  dbCredentials: {
    host: Deno.env.get('DB_HOST') ?? 'localhost',
    port: Number(Deno.env.get('DB_PORT') ?? 3306),
    user: Deno.env.get('DB_USER')!,
    password: Deno.env.get('DB_PASS') ?? '',
    database: Deno.env.get('DB_NAME')!,
  },
})
