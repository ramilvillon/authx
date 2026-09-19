# authx

A self-hosted auth server for TypeScript service backends: users, organizations,
and per-service RBAC, issuing RS256 access tokens scoped to one service's
audience. Services verify tokens locally against the published JWKS, with no
call back to authx; machine-to-machine callers get the same tokens through
`client_credentials`. Built with Deno, Hono, Drizzle, and MySQL.

## Features

- **OAuth2 auth** — password grant + refresh grant with rotation and
  reuse-detection (`/oauth/token`, `/oauth/revoke`)
- **RS256 + JWKS** — tokens signed with an RSA keypair; public key published at
  `/.well-known/jwks.json` so services verify locally (OIDC discovery at
  `/.well-known/openid-configuration`)
- **Audience-scoped tokens** — `audience` param on `/oauth/token` mints a token
  carrying exactly that service's permissions for the user
- **Multi-org + management API** — orgs, app services, members, and per-service
  RBAC managed via the management API, gated by the reserved `platform` audience
- **OpenID Connect** — id_token on the authorization_code flow, /oauth/userinfo,
  standard email/profile claims, full discovery document
- **SSO (Authorization Code + PKCE)** — `GET/POST /oauth/authorize` with a
  server-side session; `grant_type=authorization_code` on `/oauth/token`
  exchanges a one-time PKCE-protected code for audience-scoped tokens
- **Email flows over SMTP** — verification on registration, password reset, and
  confirmed email change and account deletion, all by single-use emailed links
- **Soft-deleted accounts** — a deleted account is kept for
  `ACCOUNT_PURGE_GRACE`, then erased by `db:prune`
- **Sign in with Google** — a button on the SSO login page; ends in the same
  authorization code as a password login, verified Google email required
- **M2M (client_credentials)** — a confidential service exchanges client_id +
  client_secret for a short-lived audience-scoped token whose scope is its RBAC
  permissions in the target service
- **Key rotation** — multiple keys in JWKS with a kid header; verify-by-kid
- **RBAC** — roles + permissions with ownership checks (self-or-permission)
- **Pluggable rate limiting** — in-memory store, stricter throttle on auth
  routes
- **Drizzle ORM + MySQL** — interface-based repositories with in-memory fakes
  for tests
- **OpenAPI + Scalar docs** — served at `/openapi` and `/docs`
- **Type-safe RPC client** — `hc<AppType>` exported from `src/client.ts`
- **Pre-commit gate** — husky + gitleaks + `deno fmt`/`lint`/`check`

## Prerequisites

- [asdf](https://asdf-vm.com/) (pins Deno, Node, gitleaks via `.tool-versions`)
- A Docker engine for MySQL and Mailpit: Docker Desktop, or
  [Colima](https://github.com/abiosoft/colima) (`colima start` before any `make`
  target that touches containers)

```bash
asdf install          # installs deno, nodejs, gitleaks at pinned versions
npm install           # installs husky and activates the pre-commit hook
```

## Setup

```bash
make bootstrap   # .env with a fresh JWT keypair, MySQL + Mailpit, migrations, seed
make dev         # start the API with --watch
```

Set `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` in `.env` and re-run
`make seed` to get a platform admin. `make` alone lists every target:

| Target                                 | What it does                                                           |
| -------------------------------------- | ---------------------------------------------------------------------- |
| `make setup`                           | create `.env` from `.env.example` + JWT keypair (skips if present)     |
| `make up` / `stop` / `status` / `logs` | start (and wait for healthy) / stop, keeping data / list / follow logs |
| `make down`                            | remove containers **and the database volume**                          |
| `make migrate` / `seed`                | apply migrations / seed the platform tenant + bootstrap admin          |
| `make db-reset`                        | wipe the database and rebuild it from migrations + seed                |
| `make studio` / `db-shell`             | browse the DB in Drizzle Studio / open a mysql shell                   |
| `make test` / `check`                  | unit + integration tests / fmt, lint, typecheck                        |

Don't build `.env` with `cp .env.example .env && deno task keys:gen >> .env`:
`--env-file` keeps the first value of a duplicated key, so the template's empty
`JWT_PRIVATE_KEY=` wins and the keys load empty. `make setup` strips those lines
first.

Mail is delivered to Mailpit by default; read it at http://localhost:8025.

The server listens on `PORT` (default `3000`). Smoke test:

```bash
curl localhost:3000/health      # {"status":"ok"}
```

## Environment

Copy `.env.example` to `.env` and adjust. Config is validated at startup
(`src/config.ts`); missing required values fail fast.

| Variable                   | Default                              | Notes                                                                                                           |
| -------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| `PORT`                     | `3000`                               | HTTP port                                                                                                       |
| `LOG_LEVEL`                | `debug`                              | `debug` enables pino-pretty output                                                                              |
| `DB_HOST`                  | `localhost`                          | MySQL host                                                                                                      |
| `DB_PORT`                  | `3306`                               | MySQL port (keep in sync with `MYSQL_PORT`)                                                                     |
| `DB_USER`                  | —                                    | **required**; MySQL user                                                                                        |
| `DB_PASS`                  | _(empty)_                            | MySQL password                                                                                                  |
| `DB_NAME`                  | —                                    | **required**; MySQL database name                                                                               |
| `JWT_PRIVATE_KEY`          | —                                    | **required**; RS256 private key (PEM). `deno task keys:gen`                                                     |
| `JWT_PUBLIC_KEY`           | —                                    | **required**; RS256 public key (PEM), published via JWKS                                                        |
| `JWT_ISSUER`               | —                                    | **required**; `iss` claim + OIDC issuer URL                                                                     |
| `JWT_PREVIOUS_PUBLIC_KEYS` | `[]`                                 | retired signing public keys still honored during rotation                                                       |
| `BOOTSTRAP_ADMIN_EMAIL`    | _(unset)_                            | optional; if set with password, `db:seed` creates a platform admin                                              |
| `BOOTSTRAP_ADMIN_PASSWORD` | _(unset)_                            | optional; bootstrap admin password; `change-me-please` is refused                                               |
| `ACCESS_TOKEN_TTL`         | `900`                                | access-token lifetime (seconds)                                                                                 |
| `REFRESH_TOKEN_TTL`        | `2592000`                            | refresh-token lifetime (seconds)                                                                                |
| `SSO_SESSION_TTL`          | `2592000`                            | SSO session lifetime (seconds)                                                                                  |
| `AUTH_CODE_TTL`            | `60`                                 | authorization-code lifetime (seconds)                                                                           |
| `EMAIL_VERIFICATION_TTL`   | `86400`                              | email-verification link lifetime (seconds)                                                                      |
| `SMTP_HOST`                | _(empty)_                            | the switch: set it to send over SMTP, leave empty for the log sender. `.env.example` sets `127.0.0.1` (Mailpit) |
| `SMTP_PORT`                | `587`                                | `587` upgrades with STARTTLS, `465` needs `SMTP_SECURE=true`. `.env.example` sets `1025` (Mailpit)              |
| `SMTP_USER`                | _(empty)_                            | SMTP username; empty sends without auth (Mailpit needs none)                                                    |
| `SMTP_PASS`                | _(empty)_                            | SMTP password                                                                                                   |
| `SMTP_SECURE`              | `false`                              | `true` for implicit TLS on connect (port 465)                                                                   |
| `EMAIL_FROM`               | _(empty)_                            | sender address, e.g. `"authx <no-reply@example.com>"`                                                           |
| `EMAIL_LOG_LINKS`          | `false`                              | set `true` only in local dev; logs the verification link + address                                              |
| `PRUNE_RETENTION`          | `2592000` (30d)                      | how long expired rows are kept before `db:prune` removes them; also the replay-detection window                 |
| `ACCOUNT_PURGE_GRACE`      | `2592000` (30d)                      | how long a deleted account stays recoverable before `db:prune` erases it                                        |
| `GOOGLE_CLIENT_ID`         | —                                    | Google OAuth client ID                                                                                          |
| `GOOGLE_CLIENT_SECRET`     | —                                    | Google OAuth client secret                                                                                      |
| `GOOGLE_REDIRECT_URI`      | `http://localhost:3000/oauth/google` | must equal the `/oauth/google` route                                                                            |
| `RATE_LIMIT_WINDOW_MS`     | `60000`                              | global limiter window                                                                                           |
| `RATE_LIMIT_MAX`           | `100`                                | global limiter max requests/window                                                                              |
| `GUEST_RATE_LIMIT`         | `10`                                 | per-IP max `POST /users/guest` creations per `RATE_LIMIT_WINDOW_MS`                                             |
| `TRUST_PROXY`              | `0`                                  | number of trusted proxy hops; `0` ignores `X-Forwarded-For`                                                     |

`TRUST_PROXY` must be the **exact** number of reverse proxies in front of this
service (`2` behind Cloudflare -> nginx, `0` when directly exposed). Proxies
append to `X-Forwarded-For`, so the client IP for rate limiting is read that
many entries from the right and everything to the left — which the caller can
forge — is ignored. Too low a count shares one rate-limit bucket between
clients; too high a count lets a caller pick its own bucket. Legacy
`true`/`false` still parse as `1`/`0`, and `true` logs a startup warning.

### Google OAuth

1. Create OAuth credentials in the Google Cloud Console.
2. Add `http://localhost:3000/oauth/google` as an authorized redirect URI.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`.

With these set, the `/oauth/authorize` login page shows **Sign in with Google**.
Google login is part of the authorization code flow, not a separate way to get
tokens: the link carries the pending authorize request to `/oauth/google`, which
remembers it in a short-lived cookie and redirects to Google. On the way back
the user gets the same SSO session and `302` to `redirect_uri?code=…&state=…` as
after a password login, and the client exchanges the code as usual. The route
serves both legs, so its path must match `GOOGLE_REDIRECT_URI`.

A Google login is refused, back on the login page, when the Google email is
unverified or when a local account with that email has a password or an
unverified email (sign in with the password first). Cancelling at Google also
returns to the login page. Without `GOOGLE_CLIENT_ID` the button is hidden and
the route returns 404.

### Guest accounts

A service opts in with `guestsEnabled`, set at `POST /orgs/:id/services` or
afterwards with `PATCH /services/:id` (`{ "guestsEnabled": true }`).
`POST /users/guest` then takes `{ "client_id": "<cid>" }`, unauthenticated, and
creates an account with a generated username and password and no email,
returning `{ username, password }` **once** — they are not retrievable again, so
the client stores them and re-authenticates on relaunch with
`grant_type=password`, which accepts a `username` as well as an email in that
field.

The account binds to Google later, while authenticated, via
`POST /users/me/social-links`
(`{ "provider": "google", "code": "<server auth
code>" }`), taking a one-time
**server auth code from a native Google SDK** — not an id_token, and not the
browser redirect flow's authorization code. A successful bind adds the Google
address as a second, verified sign-in identifier; the generated username and
password keep working unchanged.

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

## API endpoints

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
| `GET`    | `/verify-email`                     | —                                  | Verify via emailed token                                                                                                                     |
| `POST`   | `/verify-email/resend`              | —                                  | Resend verification email (always 204)                                                                                                       |
| `POST`   | `/oauth/token`                      | —                                  | OAuth2 password, refresh, code, or client_credentials grant                                                                                  |
| `POST`   | `/oauth/revoke`                     | —                                  | Revoke a refresh token                                                                                                                       |
| `GET`    | `/oauth/google`                     | —                                  | Sign in with Google, linked from the authorize login page (redirect + return)                                                                |
| `GET`    | `/oauth/authorize`                  | —                                  | Start SSO; login form or 302 with `?code`                                                                                                    |
| `POST`   | `/oauth/authorize`                  | —                                  | Submit login; sets session, 302 with `?code`                                                                                                 |
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
rejected with 400.

Permission keys are defined per service, so the `users:*` permissions above
count only on a token minted for the reserved `platform` audience — the same key
granted inside a tenant service authorizes nothing on `/users`. Acting on your
own record (self) works with a token for any audience.

### The user representation

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
should note both: **`email` is nullable** (a guest has no address until it binds
one) and **`username` was added** (null for a registered user, set for a guest).
Nothing consumed the response before guests shipped, so no version of this
document ever described a non-nullable `email` — it is recorded here so the
change is not rediscovered as a bug.

Guest usernames are deliberately included on the operator-facing listings. They
are not a credential (the password is), and the routes already restrict who can
see them: `users:list` and `users:read:any` count only on the reserved
`platform` audience, so a tenant token reaches nothing but its own row. Removing
the field would leave an operator looking at a bare id with a null email and no
way to tell which account it is.

### Management API

These routes require a Bearer token minted for the reserved `platform` audience
(`requireAuth` + `requirePlatform`) plus the listed permission.

| Method   | Path                        | Permission       | Description                                                  |
| -------- | --------------------------- | ---------------- | ------------------------------------------------------------ |
| `POST`   | `/orgs`                     | `orgs:write`     | Create an organization                                       |
| `GET`    | `/orgs`                     | `orgs:read`      | List organizations                                           |
| `GET`    | `/orgs/:id`                 | `orgs:read`      | Get an organization                                          |
| `POST`   | `/orgs/:id/services`        | `services:write` | Register a service (one-time secret)                         |
| `GET`    | `/orgs/:id/services`        | `services:read`  | List an org's services                                       |
| `PATCH`  | `/services/:id`             | `services:write` | Update a service's `name`, `redirectUris` or `guestsEnabled` |
| `POST`   | `/orgs/:id/members`         | `members:write`  | Add a member                                                 |
| `DELETE` | `/orgs/:id/members/:userId` | `members:write`  | Remove a member                                              |
| `POST`   | `/services/:id/roles`       | `rbac:write`     | Create a role for a service                                  |
| `POST`   | `/services/:id/permissions` | `rbac:write`     | Create a permission for a service                            |
| `POST`   | `/roles/:id/permissions`    | `rbac:write`     | Grant a permission to a role                                 |
| `POST`   | `/users/:userId/roles`      | `rbac:write`     | Assign a role to a user                                      |
| `POST`   | `/clients/:clientId/roles`  | `rbac:write`     | Grant a role to a client (M2M principal)                     |

Setting `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` before
`deno task
db:seed` creates that user as a platform `admin`. Both are empty in
`.env.example`, so pick your own values; `db:seed` aborts if the password is
still the `change-me-please` placeholder older templates shipped. Get an admin
token with a password grant for `audience: "platform"`.

Example password-grant flow (`username` accepts a registered user's email or a
guest's generated username):

```bash
# obtain a token pair
curl -X POST localhost:3000/oauth/token \
  -H 'content-type: application/json' \
  -d '{"grant_type":"password","username":"a@b.com","password":"pw123456","audience":"platform"}'

# call a protected route
curl localhost:3000/users/me -H "authorization: Bearer <access_token>"
```

### Authorization Code + PKCE (SSO)

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
  -H 'content-type: application/json' \
  -d '{"grant_type":"authorization_code","code":"<code>","redirect_uri":"<uri>","code_verifier":"<verifier>","client_id":"<client_id>"}'
```

Confidential clients also send `"client_secret":"…"`. Only PKCE `S256` is
supported.

### OIDC

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

### Email verification

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

### Key rotation

Generate a new pair (`deno task keys:gen`) → set it as
`JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`, move the old public PEM into
`JWT_PREVIOUS_PUBLIC_KEYS` (JSON array) → deploy. Both keys appear in JWKS so
verifiers pick by `kid`; drop the retired public key after the access-token TTL
elapses.

### M2M (client_credentials)

```bash
curl -X POST localhost:3000/oauth/token \
  -H 'content-type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"<cid>","client_secret":"<secret>","audience":"<target-audience>"}'
```

## Errors

All error responses use a consistent envelope:

```json
{ "error": { "code": "<machine_code>", "message": "..." } }
```

The HTTP status reflects the error class (400 / 401 / 403 / 404 / 409). `code`
is a stable machine-readable identifier from the catalogue in
`src/lib/errors.ts` (e.g. `invalid_grant`, `user_not_found`, `email_taken`).
Clients should branch on `code`, not on the human-readable `message` — messages
may be revised without a version bump; codes are stable.

## Type-safe RPC client

`src/client.ts` exports an `hc<AppType>` client typed by the live route tree.
Import it from another Deno/TypeScript project to call the API with full
inference on paths, params, and response bodies.

## Development

```bash
deno task dev               # run with --watch
deno task test              # run every test (deno test -A)
deno task test:unit         # tests/unit — pure logic, no I/O
deno task test:integration  # tests/integration — full app via app.request
deno task test:e2e          # tests/e2e — real MySQL (loads .env)
make test-db                # tests/integration again, on real MySQL (fresh app_test database)
deno task check:all         # fmt --check + lint + type-check (CI/pre-commit gate)
deno task fmt               # format
deno task lint              # lint
```

Tests are grouped by scope under `tests/`:

| Folder         | What it covers                                                        | Needs MySQL |
| -------------- | --------------------------------------------------------------------- | ----------- |
| `unit/`        | Pure functions and single middleware/services against in-memory fakes | No          |
| `integration/` | The full app booted in-memory, exercised over HTTP via `app.request`  | No          |
| `e2e/`         | Real adapters against a live database (the Drizzle repository)        | Yes         |

`deno task test` runs all of them; the e2e tests self-skip when `DB_NAME` is
unset (so they're ignored unless you run `deno task test:e2e`, which loads
`.env`). Shared fixtures live in `tests/helpers.ts`.

The integration suite also runs against MySQL: `make test-db` recreates an
`app_test` database, migrates and seeds it, and runs `tests/integration` with
`TEST_DB=mysql`, which swaps the in-memory fakes for the Drizzle repositories
and restores the seeded tables before every test. The fakes are more permissive
than MySQL, so a flow can pass in-memory and fail here. It refuses any `DB_NAME`
not ending in `_test`, because it truncates every table. CI runs it in the e2e
workflow.

### Pre-commit hook

`npm install` activates a husky `pre-commit` hook that runs, in order:
`gitleaks protect`, `deno fmt --check`, `deno lint`, and
`deno check src/ tests/`. A commit is blocked if any step fails.

## Database tasks

```bash
deno task db:generate   # generate a migration from schema changes
deno task db:migrate    # apply migrations
deno task db:seed       # seed the platform tenant + bootstrap admin
deno task db:prune      # delete expired rows + erase deleted accounts (run on a schedule)
deno task keys:gen      # print a fresh RS256 keypair as JWT_PRIVATE_KEY/JWT_PUBLIC_KEY env lines
```
