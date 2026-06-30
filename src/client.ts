import { hc } from 'hono/client'
import type { AppType } from './app.ts'

export type { AppType }

export function createClient(baseUrl: string, init?: Parameters<typeof hc>[1]) {
  return hc<AppType>(baseUrl, init)
}
