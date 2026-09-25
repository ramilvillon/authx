import { assert, assertFalse } from '@std/assert'
import {
  passkeyRegisterScript,
  passkeySignInScript,
} from '../../src/modules/passkeys/passkey-script.ts'

// A <script> element closes on the first `</script` an HTML tokenizer sees,
// even inside a JS comment or string literal -- it does not parse JS at that
// point. A comment that spells out the literal closing tag (to explain why
// dynamic data is escaped, say) closes its own element early and truncates
// everything after it. Guards both inline scripts against that.
function scriptBody(html: string): string {
  const OPEN = '<script>'
  const CLOSE = '</script>'
  assert(html.startsWith(OPEN), 'expected the script to open with <script>')
  assert(html.endsWith(CLOSE), 'expected the script to end with </script>')
  return html.slice(OPEN.length, html.length - CLOSE.length)
}

function assertParses(html: string) {
  const body = scriptBody(html)
  assertFalse(
    /<\/script/i.test(body),
    'a closing script tag inside the body would truncate the element early',
  )
  assertFalse(
    body.includes('<!--'),
    'an HTML comment inside the body is not a JS comment',
  )
  // Parses (not runs) the body as a function; throws SyntaxError on anything
  // that would not survive being embedded in a real <script> element.
  new Function(body)
}

Deno.test('passkeySignInScript has no unescaped script-closing tag and parses as JS', () => {
  assertParses(passkeySignInScript)
})

Deno.test('passkeyRegisterScript has no unescaped script-closing tag and parses as JS', () => {
  assertParses(passkeyRegisterScript('/oauth/authorize?state=%3C%2Fscript%3E'))
})
