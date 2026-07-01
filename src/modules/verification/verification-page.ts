// ponytail: minimal server-rendered pages, same style as the login page — no template dep.
function page(title: string, body: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1><p>${body}</p></body></html>`
}

export function verificationSuccessPage(): string {
  return page(
    'Email verified',
    'Your email address has been verified. You can close this tab.',
  )
}

export function verificationErrorPage(): string {
  return page(
    'Verification failed',
    'This verification link is invalid or has expired. Request a new one.',
  )
}
