# deno-hono-api-starter

A production-shaped REST API starter built with Deno, Hono, and TypeScript.
Factory-function composition (no inheritance), dependencies flow inward
(`config → db → repositories → services → deps`), and route modules stay
dependency-free so the `hc` RPC client keeps full type inference.

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
- **SSO (Authorization Code + PKCE)** — `GET/POST /oauth/authorize` with a
  server-side session; `grant_type=authorization_code` on `/oauth/token`
  exchanges a one-time PKCE-protected code for audience-scoped tokens
- **Google social login** — verified-email requirement (`/oauth/google`)
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
- Docker (for MySQL, and optionally Redis)

```bash
asdf install          # installs deno, nodejs, gitleaks at pinned versions
npm install           # installs husky and activates the pre-commit hook
```

## Setup

```bash
cp .env.example .env
deno task keys:gen >> .env       # generate the RS256 keypair, append to .env
docker compose up -d mysql      # start MySQL
deno task db:migrate            # apply Drizzle migrations
deno task db:seed               # seed the platform tenant + bootstrap admin
deno task dev                   # start the API with --watch
```

The server listens on `PORT` (default `3000`). Smoke test:

```bash
curl localhost:3000/health      # {"status":"ok"}
```

## Environment

Copy `.env.example` to `.env` and adjust. Config is validated at startup
(`src/config.ts`); missing required values fail fast.

| Variable                   | Default                              | Notes                                                              |
| -------------------------- | ------------------------------------ | ------------------------------------------------------------------ |
| `PORT`                     | `3000`                               | HTTP port                                                          |
| `LOG_LEVEL`                | `debug`                              | `debug` enables pino-pretty output                                 |
| `DB_HOST`                  | `localhost`                          | MySQL host                                                         |
| `DB_PORT`                  | `3306`                               | MySQL port (keep in sync with `MYSQL_PORT`)                        |
| `DB_USER`                  | —                                    | **required**; MySQL user                                           |
| `DB_PASS`                  | _(empty)_                            | MySQL password                                                     |
| `DB_NAME`                  | —                                    | **required**; MySQL database name                                  |
| `JWT_PRIVATE_KEY`          | —                                    | **required**; RS256 private key (PEM). `deno task keys:gen`        |
| `JWT_PUBLIC_KEY`           | —                                    | **required**; RS256 public key (PEM), published via JWKS           |
| `JWT_ISSUER`               | —                                    | **required**; `iss` claim + OIDC issuer URL                        |
| `JWT_PREVIOUS_PUBLIC_KEYS` | `[]`                                 | retired signing public keys still honored during rotation          |
| `BOOTSTRAP_ADMIN_EMAIL`    | _(unset)_                            | optional; if set with password, `db:seed` creates a platform admin |
| `BOOTSTRAP_ADMIN_PASSWORD` | _(unset)_                            | optional; password for the bootstrap admin                         |
| `ACCESS_TOKEN_TTL`         | `900`                                | access-token lifetime (seconds)                                    |
| `REFRESH_TOKEN_TTL`        | `2592000`                            | refresh-token lifetime (seconds)                                   |
| `SSO_SESSION_TTL`          | `2592000`                            | SSO session lifetime (seconds)                                     |
| `AUTH_CODE_TTL`            | `60`                                 | authorization-code lifetime (seconds)                              |
| `GOOGLE_CLIENT_ID`         | —                                    | Google OAuth client ID                                             |
| `GOOGLE_CLIENT_SECRET`     | —                                    | Google OAuth client secret                                         |
| `GOOGLE_REDIRECT_URI`      | `http://localhost:3000/oauth/google` | must equal the `/oauth/google` route                               |
| `RATE_LIMIT_WINDOW_MS`     | `60000`                              | global limiter window                                              |
| `RATE_LIMIT_MAX`           | `100`                                | global limiter max requests/window                                 |
| `TRUST_PROXY`              | `false`                              | set `true` only behind a trusted proxy (honors `X-Forwarded-For`)  |
| `REDIS_URL`                | _(unset)_                            | optional; enable for a shared rate-limit store                     |

### Google OAuth

1. Create OAuth credentials in the Google Cloud Console.
2. Add `http://localhost:3000/oauth/google` as an authorized redirect URI.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`.

The `/oauth/google` route both initiates the redirect and handles the callback;
the route path must match `GOOGLE_REDIRECT_URI`. Logins with an unverified email
are rejected.

## API endpoints

| Method   | Path                                | Auth                               | Description                                                 |
| -------- | ----------------------------------- | ---------------------------------- | ----------------------------------------------------------- |
| `GET`    | `/health`                           | —                                  | Liveness check                                              |
| `POST`   | `/users`                            | —                                  | Register a user (gets `user` role)                          |
| `GET`    | `/users/me`                         | Bearer                             | Current authenticated user                                  |
| `GET`    | `/users`                            | Bearer + `users:list`              | List users                                                  |
| `GET`    | `/users/:id`                        | Bearer, self or `users:read:any`   | Get a user                                                  |
| `PATCH`  | `/users/:id`                        | Bearer, self or `users:update:any` | Update a user                                               |
| `DELETE` | `/users/:id`                        | Bearer, self or `users:delete:any` | Delete a user                                               |
| `POST`   | `/oauth/token`                      | —                                  | OAuth2 password, refresh, code, or client_credentials grant |
| `POST`   | `/oauth/revoke`                     | —                                  | Revoke a refresh token                                      |
| `GET`    | `/oauth/google`                     | —                                  | Google social login (redirect + callback)                   |
| `GET`    | `/oauth/authorize`                  | —                                  | Start SSO; login form or 302 with `?code`                   |
| `POST`   | `/oauth/authorize`                  | —                                  | Submit login; sets session, 302 with `?code`                |
| `POST`   | `/oauth/logout`                     | session cookie                     | Revoke the SSO session                                      |
| `GET`    | `/.well-known/jwks.json`            | —                                  | Public signing key (JWKS)                                   |
| `GET`    | `/.well-known/openid-configuration` | —                                  | OIDC discovery document                                     |
| `GET`    | `/openapi`                          | —                                  | OpenAPI 3 spec (JSON)                                       |
| `GET`    | `/docs`                             | —                                  | Scalar API reference UI                                     |

`POST /oauth/token` accepts an optional `audience` (a service's `audience`
string); the returned access token then carries exactly the permissions that
user has in that service. Omit it for the default audience.

### Management API

These routes require a Bearer token minted for the reserved `platform` audience
(`requireAuth` + `requirePlatform`) plus the listed permission.

| Method   | Path                        | Permission       | Description                              |
| -------- | --------------------------- | ---------------- | ---------------------------------------- |
| `POST`   | `/orgs`                     | `orgs:write`     | Create an organization                   |
| `GET`    | `/orgs`                     | `orgs:read`      | List organizations                       |
| `GET`    | `/orgs/:id`                 | `orgs:read`      | Get an organization                      |
| `POST`   | `/orgs/:id/services`        | `services:write` | Register a service (one-time secret)     |
| `GET`    | `/orgs/:id/services`        | `services:read`  | List an org's services                   |
| `POST`   | `/orgs/:id/members`         | `members:write`  | Add a member                             |
| `DELETE` | `/orgs/:id/members/:userId` | `members:write`  | Remove a member                          |
| `POST`   | `/services/:id/roles`       | `rbac:write`     | Create a role for a service              |
| `POST`   | `/services/:id/permissions` | `rbac:write`     | Create a permission for a service        |
| `POST`   | `/roles/:id/permissions`    | `rbac:write`     | Grant a permission to a role             |
| `POST`   | `/users/:userId/roles`      | `rbac:write`     | Assign a role to a user                  |
| `POST`   | `/clients/:clientId/roles`  | `rbac:write`     | Grant a role to a client (M2M principal) |

Setting `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` before
`deno task
db:seed` creates that user as a platform `admin`. Get an admin token
with a password grant for `audience: "platform"`.

Example password-grant flow:

```bash
# obtain a token pair
curl -X POST localhost:3000/oauth/token \
  -H 'content-type: application/json' \
  -d '{"grant_type":"password","username":"a@b.com","password":"pw123456"}'

# call a protected route
curl localhost:3000/users/me -H "authorization: Bearer <access_token>"
```

### Authorization Code + PKCE (SSO)

1. Client generates a `code_verifier` and
   `code_challenge = base64url(sha256(verifier))`.
2. Browser hits
   `GET /oauth/authorize?client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256&state=…`.
3. No session → login form; on success the server sets an SSO session cookie and
   `302`s back to `redirect_uri?code=…&state=…`. An existing session skips the
   form.
4. Client exchanges the code:

```bash
curl -X POST localhost:3000/oauth/token \
  -H 'content-type: application/json' \
  -d '{"grant_type":"authorization_code","code":"<code>","redirect_uri":"<uri>","code_verifier":"<verifier>","client_id":"<client_id>"}'
```

Confidential clients also send `"client_secret":"…"`. Only PKCE `S256` is
supported.

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

## Type-safe RPC client

`src/client.ts` exports an `hc<AppType>` client typed by the live route tree.
Import it from another Deno/TypeScript project to call the API with full
inference on paths, params, and response bodies.

## Rate limiting with Redis

The default store is in-memory (per-process). To run a shared store:

```bash
docker compose --profile redis up -d   # starts MySQL + Redis
# set REDIS_URL=redis://localhost:6379 in .env
```

## Development

```bash
deno task dev               # run with --watch
deno task test              # run every test (deno test -A)
deno task test:unit         # tests/unit — pure logic, no I/O
deno task test:integration  # tests/integration — full app via app.request
deno task test:e2e          # tests/e2e — real MySQL (loads .env)
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

### Pre-commit hook

`npm install` activates a husky `pre-commit` hook that runs, in order:
`gitleaks protect`, `deno fmt --check`, `deno lint`, and
`deno check src/ tests/`. A commit is blocked if any step fails.

## Database tasks

```bash
deno task db:generate   # generate a migration from schema changes
deno task db:migrate    # apply migrations
deno task db:seed       # seed the platform tenant + bootstrap admin
deno task keys:gen      # print a fresh RS256 keypair as JWT_PRIVATE_KEY/JWT_PUBLIC_KEY env lines
```
