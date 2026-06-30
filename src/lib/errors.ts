import type { ContentfulStatusCode } from 'hono/utils/http-status'

export class AppError extends Error {
  readonly status: ContentfulStatusCode
  readonly code: string

  constructor(status: ContentfulStatusCode, code: string, message: string) {
    super(message)
    this.name = 'AppError'
    this.status = status
    this.code = code
  }

  static badRequest = (m: string) => new AppError(400, 'bad_request', m)
  static unauthorized = (m: string) => new AppError(401, 'unauthorized', m)
  static forbidden = (m: string) => new AppError(403, 'forbidden', m)
  static notFound = (m: string) => new AppError(404, 'not_found', m)
  static conflict = (m: string) => new AppError(409, 'conflict', m)
}
