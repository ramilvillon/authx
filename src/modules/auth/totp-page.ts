import { authorizeHiddenFields, esc } from './login-page.ts'

// ponytail: plain server-rendered HTML string, like the login page.
// One field for both kinds of code: six digits is TOTP, anything else is
// tried as a recovery code.
export function totpPage(
  params: Parameters<typeof authorizeHiddenFields>[0],
  error?: string,
): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Two-factor authentication</title></head>
<body>
  <h1>Enter your code</h1>
  ${error ? `<p role="alert">${esc(error)}</p>` : ''}
  <form method="post" action="/oauth/authorize/totp">
    ${authorizeHiddenFields(params)}
    <label>Code from your authenticator app, or a recovery code
      <input name="code" autocomplete="one-time-code" required autofocus></label>
    <button type="submit">Continue</button>
  </form>
</body></html>`
}
