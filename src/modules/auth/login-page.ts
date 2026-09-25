import { passkeySignInScript } from '../passkeys/passkey-script.ts'

// ponytail: plain server-rendered HTML string — no template engine, no JSX dep.
export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!
  ))
}

type AuthorizeFields = {
  client_id: string
  redirect_uri: string
  scope: string
  state?: string
  nonce?: string
  code_challenge: string
  code_challenge_method: string
  csrf_token: string
  prompt?: string
  passkey?: string
}

// The authorize request and the CSRF token, carried by every hosted page that
// posts back into the flow.
export function authorizeHiddenFields(params: AuthorizeFields): string {
  const hidden = (name: string, value: string) =>
    `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`
  return [
    hidden('client_id', params.client_id),
    hidden('redirect_uri', params.redirect_uri),
    hidden('scope', params.scope),
    hidden('state', params.state ?? ''),
    params.nonce ? hidden('nonce', params.nonce) : '',
    params.prompt ? hidden('prompt', params.prompt) : '',
    params.passkey ? hidden('passkey', params.passkey) : '',
    hidden('code_challenge', params.code_challenge),
    hidden('code_challenge_method', params.code_challenge_method),
    hidden('csrf_token', params.csrf_token),
  ].join('\n    ')
}

export function loginPage(
  params: AuthorizeFields,
  error?: string,
  // Present only when Google login is configured: the same authorize request,
  // sent to /oauth/google instead of posted with a password.
  googleHref?: string,
  passkeys = false,
): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
  <h1>Sign in</h1>
  ${error ? `<p role="alert">${esc(error)}</p>` : ''}
  <form method="post" action="/oauth/authorize">
    ${authorizeHiddenFields(params)}
    <label>Email <input type="email" name="email" required${
    passkeys ? ' autocomplete="username webauthn"' : ''
  }></label>
    <label>Password <input type="password" name="password" required></label>
    <button type="submit">Sign in</button>
  </form>
  ${
    googleHref
      ? `<p><a href="${esc(googleHref)}">Sign in with Google</a></p>`
      : ''
  }
  ${
    passkeys
      ? `<form id="passkey-form" method="post" action="/oauth/authorize/passkey" hidden>
    ${authorizeHiddenFields(params)}
    <input type="hidden" name="credential">
    <button type="button" id="passkey-button">Sign in with a passkey</button>
    <p id="passkey-error" role="alert" hidden>That passkey couldn't be used. Try again, or sign in with your password.</p>
  </form>
  ${passkeySignInScript}`
      : ''
  }
</body></html>`
}
