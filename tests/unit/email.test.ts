import { assert } from '@std/assert'
import { createLogEmailSender } from '../../src/lib/email.ts'

Deno.test('log email sender logs the link and resolves', async () => {
  const lines: unknown[] = []
  const fakeLogger = {
    info: (...a: unknown[]) => lines.push(a),
  } as unknown as Parameters<typeof createLogEmailSender>[0]
  const sender = createLogEmailSender(fakeLogger)
  await sender.sendVerificationEmail(
    'a@b.com',
    'http://t/verify-email?token=xyz',
  )
  assert(lines.length === 1)
  assert(JSON.stringify(lines[0]).includes('verify-email?token=xyz'))
})
