# API reference

## Endpoints

| Method   | Path                                | Auth                               | Description                                                                                                                                  |
| -------- | ----------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`    | `/health`                           | —                                  | Liveness check                                                                                                                               |
| `POST`   | `/users`                            | —                                  | Register a user (no roles; roles are per-service, granted via the management API)                                                            |
| `POST`   | `/users/guest`                      | —                                  | Create a guest account for a `client_id` with `guestsEnabled`; returns a one-time username + password                                        |
| `POST`   | `/users/me/social-links`            | Bearer                             | Bind a Google account via a native-SDK server auth code                                                                                      |
| `GET`    | `/users/me`                         | Bearer                             | Current authenticated user                                                                                                                   |
| `GET`    | `/users`                            | Bearer + `users:list`              | List users                                                                                                                                   |
| `GET`    | `/users/:id`                        | Bearer, self or `users:read:any`   | Get a user                                                                                                                                   |
| `PATCH`  | `/users/:id`                        | Bearer, self or `users:update:any` | Update a user; a self-service `password` change requires `current_password`, and a self-service `email` change is held (202) until confirmed |
| `DELETE` | `/users/:id`                        | Bearer, self or `users:delete:any` | Delete a user                                                                                                                                |
| `POST`   | `/users/me/totp`                    | Bearer                             | Start two-factor (TOTP) setup; returns a new secret + `otpauth://` URI                                                                       |
| `POST`   | `/users/me/totp/confirm`            | Bearer                             | Confirm setup with a first code; turns two-factor on, returns 10 recovery codes (shown once)                                                 |
| `DELETE` | `/users/me/totp`                    | Bearer                             | Turn two-factor off; needs `code` or `recovery_code` as proof, throttled                                                                     |
| `DELETE` | `/users/:id/totp`                   | Bearer + `users:update:any`        | Reset a user's two-factor authentication (operator; lost device and codes)                                                                   |
| `GET`    | `/verify-email`                     | —                                  | Verify via emailed token                                                                                                                     |
| `POST`   | `/verify-email/resend`              | —                                  | Resend verification email (always 204)                                                                                                       |
| `POST`   | `/oauth/token`                      | —                                  | OAuth2 password, refresh, code, or client_credentials grant                                                                                  |
| `POST`   | `/oauth/revoke`                     | —                                  | Revoke a refresh token                                                                                                                       |
| `GET`    | `/oauth/google`                     | —                                  | Sign in with Google, linked from the authorize login page (redirect + return)                                                                |
| `GET`    | `/oauth/authorize`                  | —                                  | Start SSO; login form or 302 with `?code`                                                                                                    |
| `POST`   | `/oauth/authorize`                  | —                                  | Submit login; sets session, 302 with `?code` (or the code page, for a two-factor account)                                                    |
| `POST`   | `/oauth/authorize/totp`             | `authx_mfa` challenge cookie       | Submit a TOTP or recovery code to finish a two-factor sign-in; sets session, 302 with `?code`                                                |
| `POST`   | `/oauth/logout`                     | session cookie                     | Revoke the SSO session                                                                                                                       |
| `GET`    | `/oauth/userinfo`                   | Bearer (user access token)         | OIDC UserInfo — identity claims for the token subject                                                                                        |
| `POST`   | `/oauth/userinfo`                   | Bearer (user access token)         | OIDC UserInfo — identity claims for the token subject                                                                                        |
| `GET`    | `/.well-known/jwks.json`            | —                                  | Public signing key (JWKS)                                                                                                                    |
| `GET`    | `/.well-known/openid-configuration` | —                                  | OIDC discovery document                                                                                                                      |
| `GET`    | `/openapi`                          | —                                  | OpenAPI 3 spec (JSON)                                                                                                                        |
| `GET`    | `/docs`                             | —                                  | Scalar API reference UI                                                                                                                      |

`POST /oauth/token` requires an `audience` (a service's `audience` string) on
the password and client_credentials grants; the returned access token carries
exactly the permissions that user has in that service. A request without it is
rejected with 400 `invalid_request`.

`/oauth/revoke` follows RFC 7009: the token goes in the **`token`** parameter
(`refresh_token` is still accepted), `token_type_hint` is accepted and ignored,
and success is **200** with an empty body — including for a token that is
unknown, already expired or already revoked, since the state the caller asked
for already holds.

`/oauth/token` and `/oauth/revoke` follow RFC 6749: they take
`application/x-www-form-urlencoded` bodies (what OAuth client libraries send),
and also accept JSON. A confidential client authenticates with HTTP Basic
(`client_secret_basic`, `Authorization: Basic base64(client_id:client_secret)`)
or with `client_id` + `client_secret` in the body (`client_secret_post`) — one
or the other, never both. That includes refreshing and revoking: a refresh token
issued to a confidential client can only be used or revoked with that same
client's credentials. Public clients send none. Their errors use the RFC's flat
shape rather than the envelope under [Errors](#errors), and token responses
carry `Cache-Control: no-store`.

Permission keys are defined per service, so the `users:*` permissions above
count only on a token minted for the reserved `platform` audience — the same key
granted inside a tenant service authorizes nothing on `/users`. Acting on your
own record (self) works with a token for any audience.

## The user representation

`GET /users`, `GET /users/:id`, `GET /users/me`, `POST /users` and
`PATCH /users/:id` all return the same shape:

```jsonc
{
  "id": "...",
  "email": "a@b.com", /* or null */
  "username": null, /* or "..." */
  "createdAt": "..."
}
```

Two fields changed with guest accounts, and a client parsing this strictly
should note both: **`email` is nullable** and **`username` was added**. Nothing
consumed the response before guests shipped, so no version of this document ever
described a non-nullable `email` — it is recorded here so the change is not
rediscovered as a bug.

The rule governing the two: **a username is assigned at creation and never
changes; an email can be filled in later.** Only `POST /users/guest` ever writes
a username, and no path assigns one to an existing row — so a non-null
`username` means the account was created as a guest, permanently. It does _not_
mean the account still lacks an address: a guest that binds Google has both.

|                            | `email`         | `username`  |
| -------------------------- | --------------- | ----------- |
| Registered                 | set at creation | always null |
| Guest, unbound             | null            | set         |
| Guest, after a Google bind | set             | set         |

### Login throttling

The global rate limiter is keyed on IP, which a password spray from many
addresses walks past: each address stays under the limit while one account takes
every guess. So authx also counts **consecutive failed passwords per account**
(`LOGIN_MAX_FAILURES`, default 10). At the limit that account stops accepting
passwords for `LOGIN_LOCKOUT_MS` (default 15 minutes), the correct one included
— that is what makes it work. A successful login clears the count, so an account
in daily use never accumulates its way into a lockout.

A locked account answers exactly as it would for a wrong password. A distinct
error would be an enumeration oracle: failures are only counted for accounts
that exist, so "locked" would mean "this address is registered".

**Password reset still works while an account is locked**, which is the way back
in for someone locked out by another person's guessing.

**A two-factor (TOTP) account shares this same counter with wrong codes**, not a
separate one: a correct password alone does not clear it, only a login that
completes fully does — so entering the right password still leaves the account
locked if enough wrong TOTP codes came before or after it.

### Password rules

A password a person chooses — at registration, on a self-service change, or
through a reset — must be at least 8 characters, at most 72 bytes, and must not
appear in the bundled list of ~3,900 common passwords (matched
case-insensitively). Failures are 400 `weak_password` or 400
`password_too_long`.

The 72-byte ceiling is bcrypt's: past it the extra bytes are ignored, so two
long passwords sharing a prefix would authenticate each other. authx refuses the
input rather than silently truncating it. Note the limit counts bytes, so one
emoji costs four.

A reset link is not consumed by a refused password: the rules are checked first,
so the user can submit a better one with the same link.

Generated secrets — a guest account's password — skip these rules; they are
random, and a blocklist hit on one would be a false positive.

Addresses are matched **case-insensitively** — `casey@b.com` and `CASEY@b.com`
are the same account, so the second one cannot be registered and either spelling
signs in. They are stored as they were typed; mail always goes to the stored
spelling. The same rule decides whether an address is already taken on an email
change. An address longer than 255 characters is rejected with 400.

A guest's address is filled in by the bind (`POST /users/me/social-links`, which
adopts Google's address only when there is none — a user who already has one
keeps it), or by an operator holding `users:update:any`. The self-service
`PATCH` path cannot do it: the confirming link goes to the account's _current_
address, so an address-less account is refused with `account_has_no_email`, as
it is for self-service deletion.

Guest usernames are deliberately included on the operator-facing listings. They
are not a credential (the password is), and the routes already restrict who can
see them: `users:list` and `users:read:any` count only on the reserved
`platform` audience, so a tenant token reaches nothing but its own row. Removing
the field would leave an operator looking at a bare id with a null email and no
way to tell which account it is.

## Two-factor authentication (TOTP)

An account turns TOTP on through the API — there is no hosted settings page. It
is a property of the person, not of any one app: one flag covers every audience,
so turning it on while signed into app X means app Y asks for a code too on its
next hosted login. **Turning it on does not sign out sessions or refresh tokens
that already exist** — those keep working until they expire; only a hosted login
started afterwards is asked for a code.

All four routes require a Bearer token (`requireAuth`); a `client_credentials`
(service) token names no user and gets 404, as on `/users/me`. Every route also
answers 404 `totp_not_configured` when `TOTP_ENCRYPTION_KEY` is unset —
two-factor authentication is simply not offered.

| endpoint                      | body                                             | success                                                                               | errors                                                                                                                                                                    |
| ----------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /users/me/totp`         | —                                                | 200 `{ secret, otpauth_uri }`; creates or overwrites a pending (unconfirmed) setup    | 404 `totp_not_configured` · 409 `totp_already_enabled`                                                                                                                    |
| `POST /users/me/totp/confirm` | `{ code }`                                       | 200 `{ recovery_codes: string[10] }`, shown once and never again; turns two-factor on | 400 `totp_invalid_code` · 404 `totp_not_pending` (or `totp_not_configured`) · 409 `totp_already_enabled`                                                                  |
| `DELETE /users/me/totp`       | exactly one of `{ code }` or `{ recovery_code }` | 204; deletes the secret and every recovery code                                       | 400 neither or both sent · 401 `invalid_credentials` (wrong proof), throttled — 429 after 5 wrong proofs per account in the rate-limit window · 404 `totp_not_configured` |
| `DELETE /users/:id/totp`      | —                                                | 204; operator reset (idempotent)                                                      | 403 missing `users:update:any` on a platform-audience token · 404 `totp_not_configured`                                                                                   |

`otpauth_uri` is
`otpauth://totp/<issuer host>:<email or username>?secret=…&issuer=<issuer host>&algorithm=SHA1&digits=6&period=30`
— draw it as a QR code client-side.

`DELETE /users/:id/totp` (the operator reset) needs `users:update:any` on a
**platform**-audience token; it is permission-only, not self-or-permission — a
user turning off their own two-factor goes through `DELETE /users/me/totp` and
presents proof instead. The permission gains no new power: its holder can
already change a user's email or trigger a password reset. It exists for someone
who lost both their device and their recovery codes; afterwards they sign in
with their password alone and set two-factor up again.

### Hosted flow

`GET`/`POST /oauth/authorize` are unchanged for an account without TOTP. For one
that has it on, the password form (or a Google sign-in) is followed by a code
page instead of a session: a signed **`authx_mfa`** challenge cookie (HttpOnly,
`SameSite=Lax`, path `/oauth`, 5-minute lifetime) records that the first factor
already succeeded, and the page carries the pending authorize request forward as
hidden fields.

`POST /oauth/authorize/totp` takes the same authorize parameters plus one `code`
field: six digits are read as a TOTP code, anything else as a recovery code. A
missing, expired, or otherwise invalid challenge cookie sends the user back to
the login page ("Your sign-in timed out. Please sign in again."). A wrong code
and a locked account render the **same** code-page message, so there is nothing
in the response to tell one from the other: "That code is not valid. Check your
authenticator app or use a recovery code. After too many attempts, sign-in
pauses for a while." A right code opens the session and continues exactly like a
password login: redirect to `redirect_uri` with `?code=…`.

An existing SSO session still skips the login form entirely on
`GET /oauth/authorize` — and so skips TOTP too — because it already passed the
check when it was created.

### The token endpoint

The password grant (`POST /oauth/token`) refuses a two-factor account outright.
Once the password checks out, it answers **400
`{"error":"mfa_required", "error_description":…}`** instead of a token pair — an
extension error code (RFC 6749 §5.2 allows them), distinct from `invalid_grant`
so a client library doesn't read it as "bad credentials, start over". It is
returned only after the password is correct, so it reveals nothing to someone
who does not already know it (the same reasoning as `email_not_verified`). A
client that sees `mfa_required` should send the user through the authorization
code flow (`GET /oauth/authorize`) instead, where the code page is available.
The refresh grant is unaffected: a refresh token proves a login that already
happened.

## Management API

These routes require a Bearer token minted for the reserved `platform` audience
(`requireAuth` + `requirePlatform`) plus the listed permission.

| Method   | Path                                       | Permission       | Description                                                  |
| -------- | ------------------------------------------ | ---------------- | ------------------------------------------------------------ |
| `POST`   | `/orgs`                                    | `orgs:write`     | Create an organization                                       |
| `GET`    | `/orgs`                                    | `orgs:read`      | List organizations                                           |
| `GET`    | `/orgs/:id`                                | `orgs:read`      | Get an organization                                          |
| `POST`   | `/orgs/:id/services`                       | `services:write` | Register a service (one-time secret)                         |
| `GET`    | `/orgs/:id/services`                       | `services:read`  | List an org's services                                       |
| `PATCH`  | `/services/:id`                            | `services:write` | Update a service's `name`, `redirectUris` or `guestsEnabled` |
| `POST`   | `/orgs/:id/members`                        | `members:write`  | Add a member                                                 |
| `DELETE` | `/orgs/:id/members/:userId`                | `members:write`  | Remove a member                                              |
| `POST`   | `/services/:id/roles`                      | `rbac:write`     | Create a role for a service                                  |
| `POST`   | `/services/:id/permissions`                | `rbac:write`     | Create a permission for a service                            |
| `POST`   | `/roles/:id/permissions`                   | `rbac:write`     | Grant a permission to a role                                 |
| `POST`   | `/users/:userId/roles`                     | `rbac:write`     | Assign a role to a user                                      |
| `POST`   | `/clients/:clientId/roles`                 | `rbac:write`     | Grant a role to a client (M2M principal)                     |
| `GET`    | `/services/:id/roles`                      | `rbac:read`      | List a service's roles, each with its permissions inlined    |
| `GET`    | `/services/:id/permissions`                | `rbac:read`      | List a service's permissions                                 |
| `GET`    | `/users/:userId/roles`                     | `rbac:read`      | List the roles a user holds                                  |
| `GET`    | `/clients/:clientId/roles`                 | `rbac:read`      | List the roles a client holds                                |
| `DELETE` | `/roles/:roleId/permissions/:permissionId` | `rbac:write`     | Revoke a permission from a role                              |
| `DELETE` | `/users/:userId/roles/:roleId`             | `rbac:write`     | Unassign a role from a user                                  |
| `DELETE` | `/clients/:clientId/roles/:roleId`         | `rbac:write`     | Unassign a role from a client                                |

Setting `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` before
`deno task
db:seed` creates that user as a platform `admin`. Both are empty in
`.env.example`, so pick your own values; `db:seed` aborts if the password is
still the `change-me-please` placeholder older templates shipped. Get an admin
token with a password grant for `audience: "platform"`.

The password grant is on by default for compatibility, but RFC 9700 (the OAuth
2.0 Security BCP) says it MUST NOT be used: the client handles the user's
password, and there is no page on which to add MFA or consent. New clients
should use the authorization code flow with PKCE. `ALLOW_PASSWORD_GRANT=false`
refuses it with `unsupported_grant_type` and drops it from discovery; a future
release makes that the default.

Example password-grant flow (`username` accepts a registered user's email or a
guest's generated username):

```bash
# obtain a token pair (form-encoded, as RFC 6749 specifies; JSON also works)
curl -X POST localhost:3000/oauth/token \
  -d grant_type=password -d username=a@b.com -d password=pw123456 \
  -d audience=platform

# call a protected route
curl localhost:3000/users/me -H "authorization: Bearer <access_token>"
```

### Revoking

The three `DELETE`s are idempotent: they answer 204 whether or not the grant was
there, because the state the caller asked for — that grant does not exist —
holds either way. The `GET`s 404 an unknown service id, which is a wrong id
rather than an empty answer.

**A revoke only affects tokens minted afterwards.** Permissions are read at
issuance and written into the access token's `scope`, so a token already in a
client's hands keeps what it was given until it expires (`ACCESS_TOKEN_TTL`, 15
minutes by default). Revoke the refresh token too if you need to cut access off
sooner.

Roles and permissions themselves cannot be deleted through the API — only
created, granted and revoked. Deleting a row that grants still reference needs a
cascade decision that has not been made.

Note `:id` on the service routes and `:clientId` on the client routes are the
service row's **UUID**, not its OAuth `client_id` string.

## Authorization Code + PKCE (SSO)

1. Client generates a `code_verifier` and
   `code_challenge = base64url(sha256(verifier))`.
2. Browser hits
   `GET /oauth/authorize?client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256&state=…`.
3. No session → login form (password, or Sign in with Google); on success the
   server sets an SSO session cookie and `302`s back to
   `redirect_uri?code=…&state=…`. An existing session skips the form.
4. Client exchanges the code:

```bash
curl -X POST localhost:3000/oauth/token \
  -d grant_type=authorization_code -d code=<code> -d redirect_uri=<uri> \
  -d code_verifier=<verifier> -d client_id=<client_id>
```

Confidential clients also send `client_secret`. Only PKCE `S256` is supported.

## OIDC

To get an `id_token`, include `openid` (plus any of `email`, `profile`) in the
authorization request scope:

```
GET /oauth/authorize?client_id=…&redirect_uri=…&scope=openid+email+profile
  &code_challenge=…&code_challenge_method=S256&state=…&nonce=<nonce>
```

The token exchange (`grant_type=authorization_code`) returns the usual access
token plus an `id_token` — a signed JWT whose `aud` is the `client_id`. The
`id_token` carries the claims for the granted scopes.

**UserInfo** — `/oauth/userinfo` accepts the user access token and returns the
same claims:

```bash
curl localhost:3000/oauth/userinfo \
  -H "authorization: Bearer <access_token>"
```

Profile claims (`name`, `given_name`, `family_name`, `picture`) are sourced from
the user's profile fields, which can be set via `PATCH /users/:id`.
`email_verified` reflects whether the user has clicked the verification link; it
is surfaced in both the id_token and the UserInfo response.

## Email verification

Registration triggers a verification email. With `SMTP_HOST` set it is sent over
SMTP (locally, to Mailpit); with it empty the log sender only records that a
mail was sent — the link embeds a live verification token and is never logged
unless you set `EMAIL_LOG_LINKS=true` in your `.env` for local development.
Clicking the link sets `email_verified: true`, which is surfaced in the OIDC
id_token and UserInfo endpoint. The resend endpoint
(`POST /verify-email/resend`) is anti-enumeration — it always returns 204
regardless of whether the address exists or is already verified. Changing a
user's email resets `email_verified` to false. An account created by Google
login starts verified: that path refuses an unverified Google email, so the
address is already proven and no link is sent. Verification is non-blocking: it
does not gate login.

## Key rotation

Generate a new pair (`deno task keys:gen`) → set it as
`JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`, move the old public PEM into
`JWT_PREVIOUS_PUBLIC_KEYS` (JSON array) → deploy. Both keys appear in JWKS so
verifiers pick by `kid`; drop the retired public key after the access-token TTL
elapses.

## M2M (client_credentials)

```bash
curl -X POST localhost:3000/oauth/token -u '<cid>:<secret>' \
  -d grant_type=client_credentials -d audience=<target-audience>
```

## Errors

Every endpoint except the two token endpoints (below) uses one envelope:

```json
{ "error": { "code": "<machine_code>", "message": "..." } }
```

The HTTP status reflects the error class (400 / 401 / 403 / 404 / 409). `code`
is a stable machine-readable identifier from the catalogue in
`src/lib/errors.ts` (e.g. `invalid_grant`, `user_not_found`, `email_taken`).
Clients should branch on `code`, not on the human-readable `message` — messages
may be revised without a version bump; codes are stable.

### Token endpoint errors (RFC 6749)

`POST /oauth/token` and `POST /oauth/revoke` answer in the flat shape RFC 6749
section 5.2 defines, because OAuth client libraries parse `error` as a string:

```json
{
  "error": "invalid_grant",
  "error_description": "refresh token reuse detected"
}
```

| `error`                  | status | when                                                                                                                                                 |
| ------------------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_request`        | 400    | a parameter is missing or malformed, or the body is neither form-encoded nor JSON                                                                    |
| `unsupported_grant_type` | 400    | `grant_type` is not `password`, `refresh_token`, `authorization_code` or `client_credentials`                                                        |
| `invalid_grant`          | 400    | wrong credentials; an unknown, expired, revoked or replayed refresh token or code; the user is not a member of the service's org                     |
| `invalid_target`         | 400    | the `audience` names no service (RFC 8707)                                                                                                           |
| `mfa_required`           | 400    | the password grant's credentials were correct, but the account has two-factor authentication on; sign in through the authorization code flow instead |
| `invalid_client`         | 401    | client authentication failed; carries `WWW-Authenticate: Basic` when the client used HTTP Basic                                                      |

`error_description` carries the catalogue message, so the specific reason (for
example reuse detection) stays readable. Branch on `error`.

## Type-safe RPC client

`src/client.ts` exports an `hc<AppType>` client typed by the live route tree.
Import it from another Deno/TypeScript project to call the API with full
inference on paths, params, and response bodies.

[← Back to README](../README.md)
