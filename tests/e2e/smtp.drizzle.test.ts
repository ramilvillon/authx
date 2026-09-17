import { assert, assertEquals } from '@std/assert'
import { loadConfig } from '../../src/config.ts'
import { createSmtpEmailSender } from '../../src/lib/email.ts'
import { createLogger } from '../../src/lib/logger.ts'

const smtpHost = Deno.env.get('SMTP_HOST')
const mailpitApi = Deno.env.get('MAILPIT_API')
const hasMail = Boolean(smtpHost && mailpitApi)

// The SMTP sender is the one piece that cannot be proven by a stub: nodemailer
// either speaks the protocol to a real server or it does not. This is the same
// lesson as the drizzle-vs-in-memory divergence -- an implementation that only
// fails against the real thing needs to meet the real thing.
Deno.test({
  name: 'the SMTP sender delivers a real message (needs SMTP + Mailpit)',
  ignore: !hasMail,
  fn: async () => {
    const config = loadConfig(Deno.env.toObject())
    const sender = createSmtpEmailSender(config, createLogger(config))
    const to = `e2e-${crypto.randomUUID()}@example.test`
    const link = 'https://auth.acme.test/confirm?token=e2e-token&a=1'

    await sender.sendLink(to, 'account_deletion', link)

    // Mailpit exposes what it received; poll briefly since delivery is async.
    let msg: Record<string, string> | undefined
    for (let i = 0; i < 20 && !msg; i++) {
      const res = await fetch(
        `${mailpitApi}/api/v1/search?query=${encodeURIComponent(to)}`,
      )
      const body = await res.json()
      msg = body.messages?.[0]
      if (!msg) await new Promise((r) => setTimeout(r, 250))
    }
    assert(msg, 'Mailpit never received the message')

    // The deletion copy must be recognisably about deletion, not a generic
    // "confirm" that a recipient cannot tell from an address verification.
    assert(/delet/i.test(msg.Subject), `unexpected subject: ${msg.Subject}`)

    const full = await (await fetch(`${mailpitApi}/api/v1/message/${msg.ID}`))
      .json()
    assert(
      full.Text.includes(link),
      'the text part must carry the working link',
    )
    assert(full.HTML.includes('&amp;'), 'the html part must escape the link')
    assertEquals(full.To[0].Address, to)
  },
})
