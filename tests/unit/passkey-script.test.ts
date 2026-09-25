import { assert, assertEquals, assertFalse } from '@std/assert'
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

// Runs the sign-in script's IIFE for real, against mocked browser globals
// passed as PARAMETERS (not real globals -- `window`, `navigator`, `fetch`,
// `PublicKeyCredential` and `Date` are all undefined/real-but-untouched on
// the Deno side, so shadowing them this way is the whole trick and needs no
// jsdom/happy-dom dependency).
function runSignInScript(now: { value: number }) {
  const body = scriptBody(passkeySignInScript)
  let credentialValue = ''
  let submitted = false
  let clickHandler: () => Promise<void> = () => Promise.resolve()
  const form = {
    hidden: true,
    credential: {
      set value(v: string) {
        credentialValue = v
      },
      get value() {
        return credentialValue
      },
    },
    querySelector: () => ({ value: 'csrf-tok' }),
    submit: () => {
      submitted = true
    },
  }
  const elements: Record<string, unknown> = {
    'passkey-form': form,
    'passkey-button': {
      addEventListener: (
        _e: string,
        fn: () => void,
      ) => (clickHandler = fn as () => Promise<void>),
    },
    'passkey-error': { hidden: true },
  }
  const document = { getElementById: (id: string) => elements[id] }
  const PublicKeyCredential = {
    isConditionalMediationAvailable: () => Promise.resolve(false),
  }
  const window = { PublicKeyCredential }
  let fetchCalls = 0
  const fetchFn = () => {
    fetchCalls++
    return Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve({ challenge: 'Y2hhbGxlbmdl', allowCredentials: [] }),
    })
  }
  const rawId = new Uint8Array([1, 2, 3])
  const navigator = {
    credentials: {
      get: () =>
        Promise.resolve({
          id: 'Y3JlZA',
          rawId,
          type: 'public-key',
          getClientExtensionResults: () => ({}),
          authenticatorAttachment: undefined,
          response: {
            clientDataJSON: new Uint8Array([1]),
            authenticatorData: new Uint8Array([2]),
            signature: new Uint8Array([3]),
            userHandle: new Uint8Array([4]),
          },
        }),
    },
  }
  const Date = { now: () => now.value }
  new Function(
    'window',
    'document',
    'navigator',
    'fetch',
    'PublicKeyCredential',
    'Date',
    body,
  )(window, document, navigator, fetchFn, PublicKeyCredential, Date)
  return {
    click: async () => {
      submitted = false
      credentialValue = ''
      await clickHandler()
      return { submitted, credentialValue, fetchCalls: () => fetchCalls }
    },
    fetchCalls: () => fetchCalls,
  }
}

Deno.test('the sign-in script re-fetches options once the cache is older than 4 minutes', async () => {
  const now = { value: 0 }
  const script = runSignInScript(now)

  await script.click()
  assertEquals(script.fetchCalls(), 1, 'first click fetches options')

  now.value += 3 * 60 * 1000
  await script.click()
  assertEquals(
    script.fetchCalls(),
    1,
    'a click within 4 minutes reuses the cached options',
  )

  now.value += 2 * 60 * 1000 // total 5 minutes since the first fetch
  await script.click()
  assertEquals(
    script.fetchCalls(),
    2,
    'a click past the 4-minute mark re-fetches, since the challenge expires at 5',
  )
})

Deno.test('passkeyRegisterScript continues to the app automatically with no WebAuthn support', () => {
  const body = scriptBody(passkeyRegisterScript('/oauth/authorize?state=x'))
  const elements: Record<string, unknown> = {
    'passkey-register': { addEventListener: () => {} },
    'passkey-error': { hidden: true },
  }
  const document = { getElementById: (id: string) => elements[id] }
  const window = {} // no PublicKeyCredential
  const location = { href: undefined as string | undefined }
  new Function('window', 'document', 'location', body)(
    window,
    document,
    location,
  )
  assertEquals(location.href, '/oauth/authorize?state=x')
})
