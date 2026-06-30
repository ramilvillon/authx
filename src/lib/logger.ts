import { pino } from 'pino'
import type { Config } from '../config.ts'

export type Logger = ReturnType<typeof pino>

export function createLogger(config: Config): Logger {
  const isDev = config.logLevel === 'debug'
  return pino({
    level: config.logLevel,
    ...(isDev
      ? { transport: { target: 'pino-pretty', options: { colorize: true } } }
      : {}),
  })
}
