import { authorizeHiddenFields, esc } from '../auth/login-page.ts'
import { passkeyRegisterScript } from './passkey-script.ts'

// ponytail: plain server-rendered HTML string, like the login page. The
// hidden fields are there for the CSRF token the script sends.
export function passkeyOfferPage(
  params: Parameters<typeof authorizeHiddenFields>[0],
  continueHref: string,
  dismissHref: string,
): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Add a passkey</title></head>
<body>
  <h1>Sign in faster next time with a passkey</h1>
  <p>Use your fingerprint, face or screen lock instead of your password.</p>
  <form id="passkey-register">
    ${authorizeHiddenFields(params)}
    <button type="submit">Create passkey</button>
  </form>
  <p id="passkey-error" role="alert" hidden>That didn't work. You can try again, or continue without one.</p>
  <p><a href="${esc(dismissHref)}">Not now</a> · <a href="${
    esc(continueHref)
  }">Continue</a></p>
  ${passkeyRegisterScript(continueHref)}
</body></html>`
}
