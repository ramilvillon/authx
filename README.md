# deno-hono-api-starter

A production-shaped REST API starter built with Deno, Hono, and TypeScript.
Factory-function composition (no inheritance), dependencies flow inward
(`config → db → repositories → services → deps`), and route modules stay
dependency-free so the `hc` RPC client keeps full type inference.

## Features

- **OAuth2 auth** — password grant + refresh grant with rotation and
  reuse-detection (`/oauth/token`, `/oauth/revoke`)
- **Google social login** — verified-email requirement (`/oauth/google`)
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
docker compose up -d mysql      # start MySQL
deno task db:migrate            # apply Drizzle migrations
deno task db:seed               # seed RBAC roles + permissions
deno task dev                   # start the API with --watch
```

The server listens on `PORT` (default `3000`). Smoke test:

```bash
curl localhost:3000/health      # {"status":"ok"}
```

## Environment

Copy `.env.example` to `.env` and adjust. Config is validated at startup
(`src/config.ts`); missing required values fail fast.

| Variable               | Default                              | Notes                                                             |
| ---------------------- | ------------------------------------ | ----------------------------------------------------------------- |
| `PORT`                 | `3000`                               | HTTP port                                                         |
| `LOG_LEVEL`            | `debug`                              | `debug` enables pino-pretty output                                |
| `DB_HOST`              | `localhost`                          | MySQL host                                                        |
| `DB_PORT`              | `3306`                               | MySQL port (keep in sync with `MYSQL_PORT`)                       |
| `DB_USER`              | —                                    | **required**; MySQL user                                          |
| `DB_PASS`              | _(empty)_                            | MySQL password                                                    |
| `DB_NAME`              | —                                    | **required**; MySQL database name                                 |
| `JWT_SECRET`           | —                                    | **required**; signs access tokens                                 |
| `ACCESS_TOKEN_TTL`     | `900`                                | access-token lifetime (seconds)                                   |
| `REFRESH_TOKEN_TTL`    | `2592000`                            | refresh-token lifetime (seconds)                                  |
| `GOOGLE_CLIENT_ID`     | —                                    | Google OAuth client ID                                            |
| `GOOGLE_CLIENT_SECRET` | —                                    | Google OAuth client secret                                        |
| `GOOGLE_REDIRECT_URI`  | `http://localhost:3000/oauth/google` | must equal the `/oauth/google` route                              |
| `RATE_LIMIT_WINDOW_MS` | `60000`                              | global limiter window                                             |
| `RATE_LIMIT_MAX`       | `100`                                | global limiter max requests/window                                |
| `TRUST_PROXY`          | `false`                              | set `true` only behind a trusted proxy (honors `X-Forwarded-For`) |
| `REDIS_URL`            | _(unset)_                            | optional; enable for a shared rate-limit store                    |

### Google OAuth

1. Create OAuth credentials in the Google Cloud Console.
2. Add `http://localhost:3000/oauth/google` as an authorized redirect URI.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`.

The `/oauth/google` route both initiates the redirect and handles the callback;
the route path must match `GOOGLE_REDIRECT_URI`. Logins with an unverified email
are rejected.

## API endpoints

| Method   | Path            | Auth                               | Description                               |
| -------- | --------------- | ---------------------------------- | ----------------------------------------- |
| `GET`    | `/health`       | —                                  | Liveness check                            |
| `POST`   | `/users`        | —                                  | Register a user (gets `user` role)        |
| `GET`    | `/users/me`     | Bearer                             | Current authenticated user                |
| `GET`    | `/users`        | Bearer + `users:list`              | List users                                |
| `GET`    | `/users/:id`    | Bearer, self or `users:read:any`   | Get a user                                |
| `PATCH`  | `/users/:id`    | Bearer, self or `users:update:any` | Update a user                             |
| `DELETE` | `/users/:id`    | Bearer, self or `users:delete:any` | Delete a user                             |
| `POST`   | `/oauth/token`  | —                                  | OAuth2 password or refresh grant          |
| `POST`   | `/oauth/revoke` | —                                  | Revoke a refresh token                    |
| `GET`    | `/oauth/google` | —                                  | Google social login (redirect + callback) |
| `GET`    | `/openapi`      | —                                  | OpenAPI 3 spec (JSON)                     |
| `GET`    | `/docs`         | —                                  | Scalar API reference UI                   |

Example password-grant flow:

```bash
# obtain a token pair
curl -X POST localhost:3000/oauth/token \
  -H 'content-type: application/json' \
  -d '{"grant_type":"password","username":"a@b.com","password":"pw123456"}'

# call a protected route
curl localhost:3000/users/me -H "authorization: Bearer <access_token>"
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
deno task db:seed       # seed RBAC roles + permissions
```
