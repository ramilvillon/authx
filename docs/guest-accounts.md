# Guest accounts

A service opts in with `guestsEnabled`, set at `POST /orgs/:id/services` or
afterwards with `PATCH /services/:id` (`{ "guestsEnabled": true }`).
`POST /users/guest` then takes `{ "client_id": "<cid>" }`, unauthenticated, and
creates an account with a generated username and password and no email,
returning `{ username, password }` **once** — they are not retrievable again, so
the client stores them and re-authenticates on relaunch with
`grant_type=password`, which accepts a `username` as well as an email in that
field. This depends on the password grant, so under `ALLOW_PASSWORD_GRANT=false`
`POST /users/guest` refuses (404 `guest_accounts_disabled`) and existing guests
cannot sign in (see [configuration](configuration.md)).

The account binds to Google later, while authenticated, via
`POST /users/me/social-links`
(`{ "provider": "google", "code": "<server auth
code>" }`), taking a one-time
**server auth code from a native Google SDK** — not an id_token, and not the
browser redirect flow's authorization code. A successful bind adds the Google
address as a second, verified sign-in identifier; the generated username and
password keep working unchanged.

Which `redirect_uri` that exchange sends is **`GOOGLE_BIND_REDIRECT_URI`**, and
the right value depends on how the client obtained the code:

| client                                          | code from               | set it to                                   |
| ----------------------------------------------- | ----------------------- | ------------------------------------------- |
| Android / iOS SDK                               | `requestServerAuthCode` | _(leave empty — no `redirect_uri` is sent)_ |
| Web / JS popup                                  | `initCodeClient`        | `postmessage`                               |
| A client that authorized against a redirect URI | its own flow            | that exact URI                              |

The default is empty, which is the native case this endpoint was built for. It
is configuration rather than a constant on purpose: only Google can accept or
reject the exchange, so the correct value cannot be established from this side —
and a wrong one is then a config change rather than a redeploy. A failure is
logged server-side with Google's own `error_description` (the client only ever
sees a generic `invalid_grant`), so the log names the cause.

Note this is **not** `GOOGLE_REDIRECT_URI`, which belongs to the browser
redirect leg at `/oauth/google`. Sending that one here is a
`redirect_uri_mismatch` against real Google.

Two things a client integration needs to know that are not obvious from the API
surface:

- **A failed token refresh should trigger a silent re-authentication with the
  stored username/password, not a sign-in prompt.** The realistic trigger is a
  restored phone backup carrying a stale refresh token onto a second device,
  where the first refresh is a replay by definition — not an attacker. The
  stored credential is still valid, so recovery is automatic; only a second
  failure (the credential itself rejected) should send the player to sign-in.
- **Google sign-in on a new device is the browser redirect flow
  (`/oauth/authorize`), never the native SDK.** There is deliberately no
  unauthenticated endpoint that accepts a server auth code as a sign-in — the
  bind endpoint above requires a bearer token. A fresh install with no stored
  credential and no existing session reaches Google only by opening
  `/oauth/authorize` (a system browser or custom tab works for a native app;
  PKCE is mandatory).

[← Back to README](../README.md)
