import type { TokenPurpose } from '../modules/verification/verification.repository.ts'

// ponytail: plain string templates, same choice as the login and verification
// pages — no template engine for four short messages.
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!
  ))
}

export type RenderedEmail = { subject: string; text: string; html: string }

// One message per purpose. They must not read alike: a link that verifies an
// address and a link that destroys an account are very different requests to
// make of someone, and the recipient can only tell them apart from what we say.
const COPY: Record<
  TokenPurpose,
  { subject: string; lead: string; note: string }
> = {
  verify_email: {
    subject: 'Confirm your email address',
    lead: 'Confirm this address to finish setting up your account.',
    note: 'If you did not create an account, you can ignore this message.',
  },
  email_change: {
    subject: 'Approve the change to your email address',
    lead: 'Someone asked to move your account to a different email address. ' +
      'This link approves that move.',
    note:
      'If you did not ask for this, do not open the link — someone else may ' +
      'have access to your account. Change your password instead.',
  },
  account_deletion: {
    subject: 'Confirm you want your account deleted',
    lead: 'This link deletes your account. You can recover it for 30 days, ' +
      'after which it is erased permanently and cannot be undone.',
    note:
      'If you did not ask for this, do not open the link — someone else may ' +
      'have access to your account. Change your password instead.',
  },
  password_reset: {
    subject: 'Reset your password',
    lead: 'This link lets you choose a new password.',
    note: 'If you did not ask for this, you can ignore this message; your ' +
      'password has not changed.',
  },
}

export function renderEmail(
  purpose: TokenPurpose,
  link: string,
): RenderedEmail {
  const { subject, lead, note } = COPY[purpose]
  return {
    subject,
    // The text part is not markup, so the URL goes in verbatim — escaping it
    // here would hand the recipient a link that does not work.
    text: `${lead}\n\n${link}\n\n${note}\n`,
    html: `<!doctype html>
<html><body>
  <p>${esc(lead)}</p>
  <p><a href="${esc(link)}">${esc(link)}</a></p>
  <p>${esc(note)}</p>
</body></html>`,
  }
}
