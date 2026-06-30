# authx — Organizations Auth Server

**Status:** approved design (2026-06-30)
**Starter:** https://github.com/ramilvillon/deno-hono-api-starter (Deno + Hono + Drizzle/MySQL)

## Goal

A standalone organizations auth server (identity provider) that issues tokens
multiple independent app services can trust. Organizations own app services;
users are members of organizations; membership grants access to that org's app
services, with roles/permissions scoped **per service**.

## Decisions (locked)

| Decision | Choice |
| --- | --- |
| Token trust | **JWKS + RS256** — services verify locally against published public keys; no shared secret, no callback. |
| Org model | **Multi-org**: a user can be a member of many orgs. |
| Role scope | **Per app service** — a member can have different roles in different services within the same org. |
| Login flows | **Password/refresh grant (Phase 1)** + **Authorization Code + PKCE SSO (Phase 2)**. |
| M2M (`client_credentials`) | **Out of scope for v1** (Phase 3, optional). |

## Core model

```
organization ──< app_service (= OAuth client / token audience)
     │              │
     │              └──< role ──< permission   (roles & perms defined per service)
     │
     └──< membership >── user
                              user ──< user_role (role implies a service)
```

- **organization** — owns app_services, has members.
- **app_service** — one OAuth client + one token audience. Has `client_id`,
  optional `client_secret_hash` (confidential clients), `redirect_uris`,
  `type` (`public` | `confidential`).
- **membership** — `user ∈ org`. Required before a user can get a token for any
  of that org's services.
- **per-service RBAC** — `roles` and `permissions` are scoped to an
  `app_service`. A user's roles are resolved **filtered to the requested
  service**, so a user can be admin in one service and viewer in another.

## Schema changes (Drizzle / MySQL)

New tables:
- `organizations` — `id`, `slug` (unique), `name`, `created_at`.
- `memberships` — `id`, `user_id`, `org_id`, `created_at`, unique `(user_id, org_id)`.
- `app_services` — `id`, `org_id`, `client_id` (unique), `client_secret_hash`
  (nullable), `name`, `slug`, `audience`, `type`, `redirect_uris` (JSON/text),
  `created_at`.
- `authorization_codes` (Phase 2) — `id`, `code_hash` (unique), `user_id`,
  `app_service_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`,
  `scope`, `expires_at`, `consumed_at`, `created_at`. Single-use, short TTL.

Modified tables:
- `roles` — add `app_service_id`; unique becomes `(app_service_id, name)`.
- `permissions` — add `app_service_id`; unique becomes `(app_service_id, key)`.
- `refresh_tokens` — add `app_service_id` so a refresh re-issues for the same audience.
- `user_roles` — unchanged shape `(user_id, role_id)`; role now implies a service.

## Tokens & keys

Switch signing from the starter's HS256 shared secret to **RS256 with a private
key** (`JWT_PRIVATE_KEY` PEM via env/config).

- `GET /.well-known/jwks.json` — published public key(s) as JWKS.
- `GET /.well-known/openid-configuration` — discovery document.
- Access-token claims:
  ```
  { iss, sub: <userId>, aud: <service audience>, org: <orgId>,
    scope: "billing:read billing:write", client_id, iat, exp }
  header: { kid }
  ```
- **No new dependency**: `hono/jwt` does RS256; Web Crypto
  (`subtle.exportKey('jwk', …)`) builds the JWKS.
- App services verify locally against JWKS and read `scope`/`org`/`aud`
  themselves — out of this server's scope.

`ponytail:` single active signing key (one `kid`). Multi-key rotation deferred
to Phase 3; upgrade path = keyed map of kid→key in config + JWKS lists all.

## Login flows

### Phase 1 — password/refresh grant, multi-service
- `POST /oauth/token` grows an `audience` param. Flow: resolve service by
  `client_id`/audience → assert caller is a member of the service's org →
  collect the user's permissions **in that service** → sign scoped token.
- `POST /oauth/revoke` unchanged. Refresh re-issues for the same audience.

### Phase 2 — Authorization Code + PKCE (true SSO)
- `GET /authorize` (`client_id`, `redirect_uri`, `scope`, `state`,
  `code_challenge`, `code_challenge_method`) → if no auth-server session, render
  a **minimal server-rendered login form**; on success set an SSO session cookie
  and 302 back with `?code`. Existing session → straight to code (the SSO).
- `POST /oauth/token` gains `grant_type=authorization_code` with PKCE
  verification against `authorization_codes`.

`ponytail:` first-party services auto-consent (no consent screen); login-page
styling deferred.

## Management API

Admin-protected via the existing RBAC, attached to a reserved **platform**
service (seeded at bootstrap):
- Orgs: `POST/GET /orgs`, `GET /orgs/:id`
- Services: `POST/GET /orgs/:id/services` (returns generated `client_id` +
  one-time `client_secret`)
- Members: `POST/DELETE /orgs/:id/members`
- Per-service RBAC: `POST /services/:id/roles`, `/permissions`,
  role↔permission grants, `POST /services/:id/members/:userId/roles`
- Existing `/users` registration & `/users/me` kept.

## Build order

0. **Phase 0** — import starter code into this repo as the baseline.
1. **Phase 1** — RS256 + JWKS, org/service/membership schema, per-service RBAC,
   audience-scoped password grant, management API, seed. A working
   multi-service auth server on its own.
2. **Phase 2** — Authorization Code + PKCE SSO + login page.
3. **Phase 3 (optional, not v1)** — `client_credentials` (M2M), key rotation,
   consent UI.

## Testing

Follow the starter's existing layers:
- `unit/` — token signing, JWKS export, PKCE verification, per-service RBAC
  resolution, against in-memory fakes.
- `integration/` — full flows via `app.request` (get token → fetch JWKS →
  verify token → call protected route).
- `e2e/` — new Drizzle repositories against live MySQL.
