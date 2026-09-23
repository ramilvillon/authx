# Development

## Prerequisites

- [asdf](https://asdf-vm.com/) (pins Deno, Node, gitleaks via `.tool-versions`)
- A Docker engine for MySQL and Mailpit: Docker Desktop, or
  [Colima](https://github.com/abiosoft/colima) (`colima start` before any `make`
  target that touches containers)

```bash
asdf install          # installs deno, nodejs, gitleaks at pinned versions
npm install           # installs husky and activates the pre-commit hook
```

## Local setup

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

## Pre-commit hook

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

[← Back to README](../README.md)
