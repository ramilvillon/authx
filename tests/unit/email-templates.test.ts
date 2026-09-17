import { assert, assertEquals } from '@std/assert'
import { renderEmail } from '../../src/lib/email-templates.ts'
import type { TokenPurpose } from '../../src/modules/verification/verification.repository.ts'

const ALL: TokenPurpose[] = [
  'verify_email',
  'email_change',
  'account_deletion',
  'password_reset',
]
const LINK = 'https://auth.acme.test/confirm?token=abc123'

Deno.test('every purpose renders a distinct subject and carries the link', () => {
  const subjects = new Set<string>()
  for (const purpose of ALL) {
    const m = renderEmail(purpose, LINK)
    assert(m.subject.length > 0, `${purpose} needs a subject`)
    subjects.add(m.subject)
    assert(m.text.includes(LINK), `${purpose} text must carry the link`)
    assert(m.html.includes(LINK), `${purpose} html must carry the link`)
  }
  // "confirm your address" and "confirm you want this account deleted" must not
  // read alike -- that is the entire reason sendLink takes a purpose.
  assertEquals(subjects.size, ALL.length, 'each purpose needs its own subject')
})

Deno.test('a destructive action says so in its own words', () => {
  const del = renderEmail('account_deletion', LINK)
  assert(/delet/i.test(del.subject), 'deletion must be named in the subject')
  assert(
    /permanent|cannot be undone|erase|30 days|recover/i.test(del.text),
    'deletion must say what it costs, not just offer a link',
  )
})

Deno.test('the link is escaped into the html, not concatenated raw', () => {
  const nasty =
    'https://auth.test/confirm?token=a&b="><script>alert(1)</script>'
  const m = renderEmail('verify_email', nasty)
  assert(!m.html.includes('<script>'), 'must not emit raw script tags')
  assert(m.html.includes('&amp;'), 'ampersands must be escaped')
  // The text part is not markup, so it carries the URL verbatim.
  assert(m.text.includes(nasty))
})
