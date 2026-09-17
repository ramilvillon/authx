// ponytail: plain server-rendered HTML string — no template engine, no JSX dep.
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!
  ))
}

export function loginPage(
  params: {
    client_id: string
    redirect_uri: string
    scope: string
    state?: string
    nonce?: string
    code_challenge: string
    code_challenge_method: string
    csrf_token: string
  },
  error?: string,
  // Present only when Google login is configured: the same authorize request,
  // sent to /oauth/google instead of posted with a password.
  googleHref?: string,
): string {
  const hidden = (name: string, value: string) =>
    `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
  <h1>Sign in</h1>
  ${error ? `<p role="alert">${esc(error)}</p>` : ''}
  <form method="post" action="/oauth/authorize">
    ${hidden('client_id', params.client_id)}
    ${hidden('redirect_uri', params.redirect_uri)}
    ${hidden('scope', params.scope)}
    ${hidden('state', params.state ?? '')}
    ${params.nonce ? hidden('nonce', params.nonce) : ''}
    ${hidden('code_challenge', params.code_challenge)}
    ${hidden('code_challenge_method', params.code_challenge_method)}
    ${hidden('csrf_token', params.csrf_token)}
    <label>Email <input type="email" name="email" required></label>
    <label>Password <input type="password" name="password" required></label>
    <button type="submit">Sign in</button>
  </form>
  ${
    googleHref
      ? `<p><a href="${esc(googleHref)}">Sign in with Google</a></p>`
      : ''
  }
</body></html>`
}
