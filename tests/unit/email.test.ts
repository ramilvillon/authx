import { assert } from '@std/assert'
import { createLogEmailSender } from '../../src/lib/email.ts'

function fakeLogger(lines: unknown[]) {
  return {
    info: (...a: unknown[]) => lines.push(a),
  } as unknown as Parameters<typeof createLogEmailSender>[0]
}

Deno.test('log email sender logs the link when explicitly enabled', async () => {
  const lines: unknown[] = []
  const sender = createLogEmailSender(fakeLogger(lines), true)
  await sender.sendVerificationEmail(
    'a@b.com',
    'http://t/verify-email?token=xyz',
  )
  assert(lines.length === 1)
  assert(JSON.stringify(lines[0]).includes('verify-email?token=xyz'))
})

Deno.test('log email sender omits token and recipient by default', async () => {
  const lines: unknown[] = []
  const sender = createLogEmailSender(fakeLogger(lines))
  await sender.sendVerificationEmail(
    'a@b.com',
    'http://t/verify-email?token=xyz',
  )
  assert(lines.length === 1)
  const logged = JSON.stringify(lines[0])
  assert(!logged.includes('xyz'), 'token must not be logged')
  assert(!logged.includes('a@b.com'), 'recipient must not be logged')
})
