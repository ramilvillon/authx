import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import type { Config } from '../../src/config.ts'
import { AppError } from '../../src/lib/errors.ts'
import { exchangeGoogleAuthCode } from '../../src/lib/google.ts'
import { createLogger } from '../../src/lib/logger.ts'
import { GOOGLE_TOKEN_ERROR_BODY, stubGoogleToken } from '../helpers.ts'

// Drives the real exchange against a Google that rejects it, through the real
// createLogger (its `destination` seam is the only way to read what was
// emitted). Returns both halves of the split -- what the caller was told and
// what the server recorded -- so each test can assert on exactly one.
async function rejectedExchange() {
  const lines: string[] = []
  const logger = createLogger({ logLevel: 'info' } as Config, {
    write: (s: string) => void lines.push(s),
  })
  const google = stubGoogleToken({}, {
    status: 400,
    body: GOOGLE_TOKEN_ERROR_BODY,
  })
  let error: unknown
  try {
    await exchangeGoogleAuthCode(
      'server-auth-code',
      { clientId: 'cid', clientSecret: 'secret' },
      logger,
    )
  } catch (e) {
    error = e
  } finally {
    google.restore()
  }
  return { error, log: lines.join('') }
}

Deno.test("a rejected Google exchange logs Google's own diagnosis", async () => {
  const { log } = await rejectedExchange()

  // This line is the ONLY thing that names the cause when a bind fails
  // against real Google; the client-facing error deliberately cannot. Verified
  // live on 2026-09-20 -- a browser-flow code redeemed with redirect_uri
  // omitted produced exactly this body. See the GOOGLE_BIND_REDIRECT_URI note
  // in config.ts for why that parameter is the thing you go and change.
  assertStringIncludes(log, 'Google token exchange failed')
  assertStringIncludes(log, 'Missing parameter: redirect_uri')
  assertStringIncludes(log, '"status":400')
})

Deno.test('a rejected Google exchange tells the caller nothing but invalid_grant', async () => {
  const { error } = await rejectedExchange()

  assert(error instanceof AppError, `expected an AppError, got: ${error}`)
  assertEquals(error.code, 'invalid_grant')
  assertEquals(error.status, 400)
  // app.ts's onError serialises err.message straight into the response body,
  // so Google's text must not reach the message either.
  assert(
    !error.message.includes('redirect_uri'),
    `Google's diagnosis leaked into the thrown error: ${error.message}`,
  )
})
