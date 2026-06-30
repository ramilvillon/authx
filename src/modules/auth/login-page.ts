// ponytail: plain server-rendered HTML string — no template engine, no JSX dep.
// ponytail: no CSRF token on this form — SameSite=Lax + required credentials make
// forced-login low-impact for first-party clients; add a pre-session CSRF token if
// third-party clients are ever supported.
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
    code_challenge: string
    code_challenge_method: string
  },
  error?: string,
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
    ${hidden('code_challenge', params.code_challenge)}
    ${hidden('code_challenge_method', params.code_challenge_method)}
    <label>Email <input type="email" name="email" required></label>
    <label>Password <input type="password" name="password" required></label>
    <button type="submit">Sign in</button>
  </form>
</body></html>`
}
