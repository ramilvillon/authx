# authx Phase 0 + Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the `deno-hono-api-starter` into a standalone organizations auth server that issues RS256, audience-scoped tokens multiple app services verify locally via JWKS.

**Architecture:** Keep the starter's factory-composition style (`config → db → repos → services → deps`). Add tenancy (organizations, app_services, memberships) and per-service RBAC. Swap JWT signing from HS256 shared-secret to RS256 with a published JWKS. Tokens carry `aud` (the target app service), `org`, and `scope` (the user's permissions in that service).

**Tech Stack:** Deno, Hono 4.6, Drizzle ORM + MySQL, zod, `hono/jwt` (RS256), Web Crypto (JWKS), bcryptjs.

## Global Constraints

- Deno + Hono 4.6.14; imports resolved via `deno.json` import map (no bare npm specifiers in code).
- `deno fmt` style: **no semicolons, single quotes** (`deno.json` enforces). Every commit must pass `deno task check:all`.
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit.
- Repositories are interface-first: every repo has an in-memory fake (used by unit/integration tests) and a Drizzle adapter (used by e2e + runtime). Mirror behavior between them.
- Token claims use OAuth conventions: `scope` is a **space-delimited** permission string; `aud` is the app service's `audience`.
- Signing key is a single active RSA key (one `kid`). `ponytail:` multi-key rotation deferred to Phase 3.
- IDs are `crypto.randomUUID()`; timestamps are `new Date()`.

---

### Task 0: Import the starter baseline

**Files:**
- Create: every file from `https://github.com/ramilvillon/deno-hono-api-starter` into the repo root (the repo currently holds only `LICENSE`).

**Interfaces:**
- Produces: the entire starter codebase as described in the spec — `src/config.ts`, `src/lib/jwt.ts`, `src/db/schema.ts`, `src/modules/**`, `tests/**`, `deno.json`, `drizzle.config.ts`, `docker-compose.yml`.

- [ ] **Step 1: Clone the starter and copy its contents over the repo (preserve the existing LICENSE and `docs/`)**

```bash
cd "$(git rev-parse --show-toplevel)"
git clone --depth 1 https://github.com/ramilvillon/deno-hono-api-starter /tmp/authx-starter
# copy everything except the starter's .git and LICENSE
rsync -a --exclude='.git' --exclude='LICENSE' /tmp/authx-starter/ ./
rm -rf /tmp/authx-starter
```

- [ ] **Step 2: Install Node tooling (husky) and confirm the toolchain**

Run:
```bash
npm install
deno task check:all
```
Expected: `fmt --check`, `lint`, and `check` all pass (the starter ships green).

- [ ] **Step 3: Run the non-DB tests to confirm the baseline works**

Run: `deno task test:unit && deno task test:integration`
Expected: all pass (e2e self-skips without `DB_NAME`).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: import deno-hono-api-starter baseline"
```

---

### Task 1: Swap token signing from HS256 to RS256

Replace the symmetric shared secret with an RSA keypair end to end. Same claim shape for now (`iss`, `sub`, `iat`, `exp`) — audience/scope come in Task 6. After this task the server behaves identically but signs asymmetrically.

**Files:**
- Create: `src/lib/keys.ts`
- Modify: `src/config.ts`, `src/lib/jwt.ts`, `src/deps.ts`, `src/main.ts`, `src/modules/auth/auth.service.ts`, `src/middleware/auth.ts`, `tests/helpers.ts`, `tests/unit/config.test.ts`
- Test: `tests/unit/keys.test.ts`, `tests/unit/jwt.test.ts` (rewrite)

**Interfaces:**
- Produces:
  - `generateRsaKeyPairPem(): Promise<{ privateKeyPem: string; publicKeyPem: string }>`
  - `type KeySet = { privateKeyPem: string; publicKeyPem: string; kid: string; jwks: { keys: JsonWebKey[] } }`
  - `loadKeySet(privateKeyPem: string, publicKeyPem: string): Promise<KeySet>`
  - `type AccessPayload = { iss: string; sub: string; iat: number; exp: number }`
  - `signAccessToken(opts: { sub: string; issuer: string; privateKeyPem: string; kid: string; ttlSeconds: number }): Promise<string>`
  - `verifyAccessToken(token: string, publicKeyPem: string): Promise<AccessPayload>`
  - `Config.jwtPrivateKey`, `Config.jwtPublicKey`, `Config.issuer` (replacing `Config.jwtSecret`)
  - `Deps.keySet: KeySet`; `AppEnv.Variables.keySet: KeySet`
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test for `src/lib/keys.ts`**

`tests/unit/keys.test.ts`:
```ts
import { assertEquals, assertExists } from '@std/assert'
import { generateRsaKeyPairPem, loadKeySet } from '../../src/lib/keys.ts'

Deno.test('loadKeySet builds a JWKS with a stable kid from the public key', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const ks = await loadKeySet(privateKeyPem, publicKeyPem)
  assertEquals(ks.jwks.keys.length, 1)
  const jwk = ks.jwks.keys[0]
  assertEquals(jwk.kty, 'RSA')
  assertEquals(jwk.alg, 'RS256')
  assertEquals(jwk.use, 'sig')
  assertEquals(jwk.kid, ks.kid)
  assertExists(jwk.n)
  // No private material leaks into the JWKS.
  assertEquals((jwk as Record<string, unknown>).d, undefined)
  // kid is deterministic for the same key.
  const again = await loadKeySet(privateKeyPem, publicKeyPem)
  assertEquals(again.kid, ks.kid)
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `deno test -A tests/unit/keys.test.ts`
Expected: FAIL — module `src/lib/keys.ts` not found.

- [ ] **Step 3: Implement `src/lib/keys.ts`**

```ts
import { decodeBase64, encodeBase64 } from '@std/encoding/base64'
import { encodeBase64Url } from '@std/encoding/base64url'

export type KeySet = {
  privateKeyPem: string
  publicKeyPem: string
  kid: string
  jwks: { keys: JsonWebKey[] }
}

const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const

function toPem(der: ArrayBuffer, label: string): string {
  const b64 = encodeBase64(new Uint8Array(der))
  const lines = b64.match(/.{1,64}/g)?.join('\n') ?? b64
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '')
  return decodeBase64(b64)
}

export async function generateRsaKeyPairPem(): Promise<
  { privateKeyPem: string; publicKeyPem: string }
> {
  const kp = await crypto.subtle.generateKey(
    { ...RSA, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['sign', 'verify'],
  )
  const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey)
  const pub = await crypto.subtle.exportKey('spki', kp.publicKey)
  return {
    privateKeyPem: toPem(priv, 'PRIVATE KEY'),
    publicKeyPem: toPem(pub, 'PUBLIC KEY'),
  }
}

// RFC 7638 JWK thumbprint: deterministic id tied to the key material, so the
// kid in token headers always matches the published JWKS without manual config.
async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const json = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(json),
  )
  return encodeBase64Url(new Uint8Array(digest))
}

export async function loadKeySet(
  privateKeyPem: string,
  publicKeyPem: string,
): Promise<KeySet> {
  const pub = await crypto.subtle.importKey(
    'spki',
    pemToDer(publicKeyPem),
    RSA,
    true,
    ['verify'],
  )
  const jwk = await crypto.subtle.exportKey('jwk', pub)
  const kid = await thumbprint(jwk)
  const publicJwk: JsonWebKey = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: 'RS256',
    use: 'sig',
    kid,
  }
  return { privateKeyPem, publicKeyPem, kid, jwks: { keys: [publicJwk] } }
}
```

- [ ] **Step 4: Run the keys test to verify it passes**

Run: `deno test -A tests/unit/keys.test.ts`
Expected: PASS.

- [ ] **Step 5: Rewrite `tests/unit/jwt.test.ts` (failing against the new signature)**

```ts
import { assertEquals } from '@std/assert'
import { signAccessToken, verifyAccessToken } from '../../src/lib/jwt.ts'
import { generateRsaKeyPairPem } from '../../src/lib/keys.ts'

Deno.test('sign + verify access token (RS256)', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://localhost:3000',
    privateKeyPem,
    kid: 'k1',
    ttlSeconds: 900,
  })
  const payload = await verifyAccessToken(token, publicKeyPem)
  assertEquals(payload.sub, 'u1')
  assertEquals(payload.iss, 'http://localhost:3000')
})
```

- [ ] **Step 6: Run it to verify it fails**

Run: `deno test -A tests/unit/jwt.test.ts`
Expected: FAIL — `signAccessToken` no longer accepts `secret`.

- [ ] **Step 7: Rewrite `src/lib/jwt.ts`**

```ts
import { decode, sign, verify } from 'hono/jwt'

export type AccessPayload = { iss: string; sub: string; iat: number; exp: number }

export async function signAccessToken(
  opts: {
    sub: string
    issuer: string
    privateKeyPem: string
    kid: string
    ttlSeconds: number
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: opts.issuer,
    sub: opts.sub,
    iat: now,
    exp: now + opts.ttlSeconds,
  }
  // hono/jwt accepts a PEM private key for RS256 and lets us set the kid header.
  return await sign(payload, opts.privateKeyPem, 'RS256')
}

export async function verifyAccessToken(
  token: string,
  publicKeyPem: string,
): Promise<AccessPayload> {
  return await verify(token, publicKeyPem, 'RS256') as AccessPayload
}

export { decode }
```

Note: `hono/jwt`'s `sign` does not expose a header param in 4.6; set `kid` by signing then re-stamping is unnecessary for verification (single key). `ponytail:` kid lives in the JWKS only for now; when rotation lands (Phase 3), switch to a signer that writes the `kid` header. Keep the `kid` field in `signAccessToken`'s options so the call sites are already rotation-ready.

- [ ] **Step 8: Update `src/config.ts` — replace `JWT_SECRET` with key + issuer config**

In the zod `schema`, replace the `JWT_SECRET` line with:
```ts
  JWT_PRIVATE_KEY: z.string().min(1),
  JWT_PUBLIC_KEY: z.string().min(1),
  JWT_ISSUER: z.string().min(1),
```
In the `Config` type, replace `jwtSecret: string` with:
```ts
  jwtPrivateKey: string
  jwtPublicKey: string
  issuer: string
```
In the returned object, replace `jwtSecret: e.JWT_SECRET,` with:
```ts
    jwtPrivateKey: e.JWT_PRIVATE_KEY,
    jwtPublicKey: e.JWT_PUBLIC_KEY,
    issuer: e.JWT_ISSUER,
```

- [ ] **Step 9: Add `keySet` to `Deps` and make `createDeps` async (`src/deps.ts`)**

- Add import: `import { type KeySet, loadKeySet } from './lib/keys.ts'`
- Add `keySet: KeySet` to the `Deps` type.
- Change `createDeps` to async and build the key set:
```ts
export async function createDeps(config: Config, db: Database): Promise<Deps> {
  const userRepo = createDrizzleUserRepository(db)
  const tokenRepo = createDrizzleRefreshTokenRepository(db)
  const socialRepo = createDrizzleSocialAccountRepository(db)
  const keySet = await loadKeySet(config.jwtPrivateKey, config.jwtPublicKey)
  return {
    config,
    keySet,
    rateStore: config.redisUrl
      ? createRedisRateLimitStore(config.redisUrl)
      : createMemoryRateLimitStore(),
    userService: createUserService({ repo: userRepo }),
    authService: createAuthService({ userRepo, tokenRepo, socialRepo, config, keySet }),
  }
}
```
- Add `keySet: KeySet` to `AppEnv.Variables` (the `& Deps &` already spreads it, so no change needed — `keySet` is part of `Deps`).

- [ ] **Step 10: Await `createDeps` in `src/main.ts`**

Change `const deps = createDeps(config, db)` to `const deps = await createDeps(config, db)`.

- [ ] **Step 11: Update `src/modules/auth/auth.service.ts` to sign with the key set**

- Add `keySet: KeySet` to the `createAuthService` deps param and import `type { KeySet } from '../../lib/keys.ts'`.
- Destructure: `const { userRepo, tokenRepo, config, keySet } = deps`.
- In `issueTokens`, replace the `signAccessToken` call with:
```ts
    const access_token = await signAccessToken({
      sub: userId,
      issuer: config.issuer,
      privateKeyPem: keySet.privateKeyPem,
      kid: keySet.kid,
      ttlSeconds: config.accessTokenTtl,
    })
```
- In `refreshGrant`, replace the inline `signAccessToken` call the same way (same five fields, `sub: existing.userId`).

- [ ] **Step 12: Update `src/middleware/auth.ts` to verify with the public key**

Replace `const payload = await verifyAccessToken(token, c.var.config.jwtSecret)` with:
```ts
    const payload = await verifyAccessToken(token, c.var.keySet.publicKeyPem)
```

- [ ] **Step 13: Update `tests/helpers.ts` to generate a test keypair via top-level await**

At the top, add:
```ts
import { generateRsaKeyPairPem, loadKeySet } from '../src/lib/keys.ts'

const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
const keySet = await loadKeySet(privateKeyPem, publicKeyPem)
```
Replace the `JWT_SECRET: 'test-secret'` line in `testEnv` with:
```ts
  JWT_PRIVATE_KEY: privateKeyPem,
  JWT_PUBLIC_KEY: publicKeyPem,
  JWT_ISSUER: 'http://test.local',
```
In the `deps` object inside `makeTestDeps`, add `keySet,` and pass `keySet` into `createAuthService({ ... , keySet })`.

- [ ] **Step 14: Update `tests/unit/config.test.ts`**

In `base`, replace the `JWT_SECRET: 'secret',` line with:
```ts
  JWT_PRIVATE_KEY: 'pk',
  JWT_PUBLIC_KEY: 'pub',
  JWT_ISSUER: 'http://localhost:3000',
```
Replace the `'loadConfig throws on missing required value'` test body's omit target from `JWT_SECRET` to `JWT_PRIVATE_KEY`:
```ts
  const { JWT_PRIVATE_KEY: _omit, ...partial } = base
  assertThrows(() => loadConfig(partial), Error, 'JWT_PRIVATE_KEY')
```

- [ ] **Step 15: Run the full non-DB suite**

Run: `deno task test:unit && deno task test:integration && deno task check:all`
Expected: all PASS (tokens now RS256; existing flows unchanged).

- [ ] **Step 16: Commit**

```bash
git add -A
git commit -m "feat: sign access tokens with RS256 keypair"
```

---

### Task 2: Publish JWKS and OIDC discovery

**Files:**
- Create: `src/modules/wellknown/wellknown.routes.ts`
- Modify: `src/app.ts`
- Test: `tests/integration/wellknown.test.ts`

**Interfaces:**
- Consumes: `c.var.keySet.jwks`, `c.var.config.issuer`, `verifyAccessToken` (in test).
- Produces: routes `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`.

- [ ] **Step 1: Write the failing integration test**

`tests/integration/wellknown.test.ts`:
```ts
import { assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'

Deno.test('jwks endpoint serves the public signing key', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/.well-known/jwks.json')
  assertEquals(res.status, 200)
  const body = await res.json()
  assertEquals(body.keys.length, 1)
  assertEquals(body.keys[0].use, 'sig')
})

Deno.test('discovery doc points at this issuer and jwks', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/.well-known/openid-configuration')
  const body = await res.json()
  assertEquals(body.issuer, 'http://test.local')
  assertEquals(body.jwks_uri, 'http://test.local/.well-known/jwks.json')
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `deno test -A tests/integration/wellknown.test.ts`
Expected: FAIL — 404 on both routes.

- [ ] **Step 3: Implement `src/modules/wellknown/wellknown.routes.ts`**

```ts
import { Hono } from 'hono'
import type { AppEnv } from '../../deps.ts'

const wellknown = new Hono<AppEnv>()
  .get('/jwks.json', (c) => c.json(c.var.keySet.jwks))
  .get('/openid-configuration', (c) => {
    const iss = c.var.config.issuer
    return c.json({
      issuer: iss,
      jwks_uri: `${iss}/.well-known/jwks.json`,
      token_endpoint: `${iss}/oauth/token`,
      authorization_endpoint: `${iss}/authorize`,
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['password', 'refresh_token'],
    })
  })

export default wellknown
```

- [ ] **Step 4: Mount it in `src/app.ts`**

Add import `import wellknown from './modules/wellknown/wellknown.routes.ts'` and add `.route('/.well-known', wellknown)` next to the other `.route(...)` calls.

- [ ] **Step 5: Run the test to verify it passes**

Run: `deno test -A tests/integration/wellknown.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: publish JWKS and OIDC discovery endpoints"
```

---

### Task 3: Tenancy schema (organizations, app_services, memberships) + RBAC scoping

**Files:**
- Modify: `src/db/schema.ts`
- Create: a generated migration under `src/db/migrations/`
- Test: none (schema change; verified by `db:generate` + `deno check`)

**Interfaces:**
- Produces (Drizzle tables): `organizations`, `appServices`, `memberships`; `roles`/`permissions` gain `appServiceId`; `refreshTokens` gains `appServiceId`.

- [ ] **Step 1: Edit `src/db/schema.ts`**

Add imports `text` and `index` to the existing `drizzle-orm/mysql-core` import line so it reads:
```ts
import {
  datetime,
  index,
  mysqlTable,
  primaryKey,
  text,
  unique,
  varchar,
} from 'drizzle-orm/mysql-core'
```
Append the new tables and modify the RBAC + refreshTokens tables:
```ts
export const organizations = mysqlTable('organizations', {
  id: varchar('id', { length: 36 }).primaryKey(),
  slug: varchar('slug', { length: 64 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  createdAt: datetime('created_at').notNull(),
})

export const appServices = mysqlTable('app_services', {
  id: varchar('id', { length: 36 }).primaryKey(),
  orgId: varchar('org_id', { length: 36 }).notNull(),
  clientId: varchar('client_id', { length: 64 }).notNull().unique(),
  clientSecretHash: varchar('client_secret_hash', { length: 255 }),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 64 }).notNull(),
  audience: varchar('audience', { length: 128 }).notNull().unique(),
  type: varchar('type', { length: 16 }).notNull(), // 'public' | 'confidential'
  redirectUris: text('redirect_uris').notNull().default('[]'), // JSON array
  createdAt: datetime('created_at').notNull(),
}, (t) => ({ orgIdx: index('app_services_org_idx').on(t.orgId) }))

export const memberships = mysqlTable('memberships', {
  id: varchar('id', { length: 36 }).primaryKey(),
  userId: varchar('user_id', { length: 36 }).notNull(),
  orgId: varchar('org_id', { length: 36 }).notNull(),
  createdAt: datetime('created_at').notNull(),
}, (t) => ({ userOrg: unique().on(t.userId, t.orgId) }))
```
Change `roles` to scope by service (replace the existing `roles` table):
```ts
export const roles = mysqlTable('roles', {
  id: varchar('id', { length: 36 }).primaryKey(),
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
  name: varchar('name', { length: 64 }).notNull(),
}, (t) => ({ serviceName: unique().on(t.appServiceId, t.name) }))
```
Change `permissions` likewise (replace the existing `permissions` table):
```ts
export const permissions = mysqlTable('permissions', {
  id: varchar('id', { length: 36 }).primaryKey(),
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
  key: varchar('key', { length: 64 }).notNull(),
}, (t) => ({ serviceKey: unique().on(t.appServiceId, t.key) }))
```
Add `appServiceId` to `refreshTokens` (insert after `userId`):
```ts
  appServiceId: varchar('app_service_id', { length: 36 }).notNull(),
```

- [ ] **Step 2: Generate the migration**

Run: `deno task db:generate`
Expected: a new `src/db/migrations/0002_*.sql` is created describing the new tables and columns.

- [ ] **Step 3: Type-check**

Run: `deno check src/`
Expected: PASS (the in-memory/drizzle repos for new tables come in later tasks; existing code still compiles).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add tenancy + per-service RBAC schema"
```

---

### Task 4: Tenancy repository (orgs, app services, memberships)

**Files:**
- Create: `src/modules/orgs/orgs.repository.ts` (interface + in-memory), `src/modules/orgs/orgs.repository.drizzle.ts`
- Test: `tests/unit/orgs-repository.test.ts`

**Interfaces:**
- Produces:
  ```ts
  type OrgRecord = { id: string; slug: string; name: string; createdAt: Date }
  type AppServiceRecord = {
    id: string; orgId: string; clientId: string; clientSecretHash: string | null
    name: string; slug: string; audience: string; type: 'public' | 'confidential'
    redirectUris: string[]; createdAt: Date
  }
  type MembershipRecord = { id: string; userId: string; orgId: string; createdAt: Date }
  type OrgRepository = {
    createOrg(o: OrgRecord): Promise<OrgRecord>
    findOrgById(id: string): Promise<OrgRecord | null>
    listOrgs(): Promise<OrgRecord[]>
    createService(s: AppServiceRecord): Promise<AppServiceRecord>
    findServiceById(id: string): Promise<AppServiceRecord | null>
    findServiceByAudience(audience: string): Promise<AppServiceRecord | null>
    listServicesByOrg(orgId: string): Promise<AppServiceRecord[]>
    addMember(m: MembershipRecord): Promise<void>
    removeMember(userId: string, orgId: string): Promise<void>
    isMember(userId: string, orgId: string): Promise<boolean>
  }
  createInMemoryOrgRepository(): OrgRepository
  createDrizzleOrgRepository(db: Database): OrgRepository
  ```
- Consumes: `Database` from `src/db/client.ts`.

- [ ] **Step 1: Write the failing test (in-memory repo)**

`tests/unit/orgs-repository.test.ts`:
```ts
import { assert, assertEquals } from '@std/assert'
import { createInMemoryOrgRepository } from '../../src/modules/orgs/orgs.repository.ts'

function now() {
  return new Date()
}

Deno.test('org + service + membership round-trips', async () => {
  const repo = createInMemoryOrgRepository()
  const org = await repo.createOrg({
    id: 'o1',
    slug: 'acme',
    name: 'Acme',
    createdAt: now(),
  })
  assertEquals((await repo.findOrgById('o1'))?.slug, 'acme')

  await repo.createService({
    id: 's1',
    orgId: org.id,
    clientId: 'cid_1',
    clientSecretHash: null,
    name: 'Billing',
    slug: 'billing',
    audience: 'acme-billing',
    type: 'public',
    redirectUris: [],
    createdAt: now(),
  })
  assertEquals((await repo.findServiceByAudience('acme-billing'))?.id, 's1')
  assertEquals((await repo.listServicesByOrg('o1')).length, 1)

  await repo.addMember({ id: 'm1', userId: 'u1', orgId: 'o1', createdAt: now() })
  assert(await repo.isMember('u1', 'o1'))
  await repo.removeMember('u1', 'o1')
  assert(!(await repo.isMember('u1', 'o1')))
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `deno test -A tests/unit/orgs-repository.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/modules/orgs/orgs.repository.ts`**

```ts
export type OrgRecord = {
  id: string
  slug: string
  name: string
  createdAt: Date
}

export type AppServiceRecord = {
  id: string
  orgId: string
  clientId: string
  clientSecretHash: string | null
  name: string
  slug: string
  audience: string
  type: 'public' | 'confidential'
  redirectUris: string[]
  createdAt: Date
}

export type MembershipRecord = {
  id: string
  userId: string
  orgId: string
  createdAt: Date
}

export type OrgRepository = {
  createOrg(o: OrgRecord): Promise<OrgRecord>
  findOrgById(id: string): Promise<OrgRecord | null>
  listOrgs(): Promise<OrgRecord[]>
  createService(s: AppServiceRecord): Promise<AppServiceRecord>
  findServiceById(id: string): Promise<AppServiceRecord | null>
  findServiceByAudience(audience: string): Promise<AppServiceRecord | null>
  listServicesByOrg(orgId: string): Promise<AppServiceRecord[]>
  addMember(m: MembershipRecord): Promise<void>
  removeMember(userId: string, orgId: string): Promise<void>
  isMember(userId: string, orgId: string): Promise<boolean>
}

// In-memory test double. Mirror behavior in orgs.repository.drizzle.ts.
export function createInMemoryOrgRepository(): OrgRepository {
  const orgs = new Map<string, OrgRecord>()
  const services = new Map<string, AppServiceRecord>()
  const members = new Set<string>() // `${userId}:${orgId}`

  return {
    createOrg(o) {
      orgs.set(o.id, { ...o })
      return Promise.resolve({ ...o })
    },
    findOrgById(id) {
      return Promise.resolve(orgs.has(id) ? { ...orgs.get(id)! } : null)
    },
    listOrgs() {
      return Promise.resolve([...orgs.values()].map((o) => ({ ...o })))
    },
    createService(s) {
      services.set(s.id, { ...s })
      return Promise.resolve({ ...s })
    },
    findServiceById(id) {
      return Promise.resolve(services.has(id) ? { ...services.get(id)! } : null)
    },
    findServiceByAudience(audience) {
      for (const s of services.values()) {
        if (s.audience === audience) return Promise.resolve({ ...s })
      }
      return Promise.resolve(null)
    },
    listServicesByOrg(orgId) {
      return Promise.resolve(
        [...services.values()].filter((s) => s.orgId === orgId).map((s) => ({
          ...s,
        })),
      )
    },
    addMember(m) {
      members.add(`${m.userId}:${m.orgId}`)
      return Promise.resolve()
    },
    removeMember(userId, orgId) {
      members.delete(`${userId}:${orgId}`)
      return Promise.resolve()
    },
    isMember(userId, orgId) {
      return Promise.resolve(members.has(`${userId}:${orgId}`))
    },
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `deno test -A tests/unit/orgs-repository.test.ts`
Expected: PASS.

- [ ] **Step 5: Implement `src/modules/orgs/orgs.repository.drizzle.ts`**

```ts
import { and, eq } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import { appServices, memberships, organizations } from '../../db/schema.ts'
import type {
  AppServiceRecord,
  OrgRepository,
} from './orgs.repository.ts'

function toService(row: typeof appServices.$inferSelect): AppServiceRecord {
  return {
    ...row,
    type: row.type as 'public' | 'confidential',
    redirectUris: JSON.parse(row.redirectUris) as string[],
  }
}

export function createDrizzleOrgRepository(db: Database): OrgRepository {
  return {
    async createOrg(o) {
      await db.insert(organizations).values(o)
      return o
    },
    async findOrgById(id) {
      const row = await db.query.organizations.findFirst({
        where: eq(organizations.id, id),
      })
      return row ?? null
    },
    async listOrgs() {
      return await db.select().from(organizations)
    },
    async createService(s) {
      await db.insert(appServices).values({
        ...s,
        redirectUris: JSON.stringify(s.redirectUris),
      })
      return s
    },
    async findServiceById(id) {
      const row = await db.query.appServices.findFirst({
        where: eq(appServices.id, id),
      })
      return row ? toService(row) : null
    },
    async findServiceByAudience(audience) {
      const row = await db.query.appServices.findFirst({
        where: eq(appServices.audience, audience),
      })
      return row ? toService(row) : null
    },
    async listServicesByOrg(orgId) {
      const rows = await db.select().from(appServices).where(
        eq(appServices.orgId, orgId),
      )
      return rows.map(toService)
    },
    async addMember(m) {
      await db.insert(memberships).values(m)
        .onDuplicateKeyUpdate({ set: { userId: m.userId } })
    },
    async removeMember(userId, orgId) {
      await db.delete(memberships).where(
        and(eq(memberships.userId, userId), eq(memberships.orgId, orgId)),
      )
    },
    async isMember(userId, orgId) {
      const row = await db.query.memberships.findFirst({
        where: and(
          eq(memberships.userId, userId),
          eq(memberships.orgId, orgId),
        ),
      })
      return !!row
    },
  }
}
```

- [ ] **Step 6: Type-check and commit**

Run: `deno check src/ tests/`
Expected: PASS.
```bash
git add -A && git commit -m "feat: tenancy repository (orgs, services, memberships)"
```

---

### Task 5: Per-service RBAC repository

Defines roles/permissions per app service, grants permissions to roles, assigns roles to members, and resolves a member's permission keys **within a single service**.

**Files:**
- Create: `src/modules/rbac/rbac.repository.ts` (interface + in-memory), `src/modules/rbac/rbac.repository.drizzle.ts`
- Test: `tests/unit/rbac-repository.test.ts`

**Interfaces:**
- Produces:
  ```ts
  type RoleRecord = { id: string; appServiceId: string; name: string }
  type PermissionRecord = { id: string; appServiceId: string; key: string }
  type RbacRepository = {
    createRole(r: RoleRecord): Promise<RoleRecord>
    createPermission(p: PermissionRecord): Promise<PermissionRecord>
    grantPermissionToRole(roleId: string, permissionId: string): Promise<void>
    assignRoleToUser(userId: string, roleId: string): Promise<void>
    findRoleById(id: string): Promise<RoleRecord | null>
    // The core query: permission keys a user holds within one app service.
    permissionsForUserInService(userId: string, appServiceId: string): Promise<string[]>
  }
  createInMemoryRbacRepository(): RbacRepository
  createDrizzleRbacRepository(db: Database): RbacRepository
  ```
- Consumes: existing `userRoles`, `roles`, `permissions`, `rolePermissions` tables (now service-scoped).

- [ ] **Step 1: Write the failing test**

`tests/unit/rbac-repository.test.ts`:
```ts
import { assertEquals } from '@std/assert'
import { createInMemoryRbacRepository } from '../../src/modules/rbac/rbac.repository.ts'

Deno.test('permissions are scoped to a service', async () => {
  const repo = createInMemoryRbacRepository()
  // billing service: admin -> billing:read
  await repo.createRole({ id: 'r1', appServiceId: 's1', name: 'admin' })
  await repo.createPermission({ id: 'p1', appServiceId: 's1', key: 'billing:read' })
  await repo.grantPermissionToRole('r1', 'p1')
  // analytics service: viewer -> analytics:read
  await repo.createRole({ id: 'r2', appServiceId: 's2', name: 'viewer' })
  await repo.createPermission({ id: 'p2', appServiceId: 's2', key: 'analytics:read' })
  await repo.grantPermissionToRole('r2', 'p2')

  await repo.assignRoleToUser('u1', 'r1')
  await repo.assignRoleToUser('u1', 'r2')

  assertEquals(await repo.permissionsForUserInService('u1', 's1'), ['billing:read'])
  assertEquals(await repo.permissionsForUserInService('u1', 's2'), ['analytics:read'])
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `deno test -A tests/unit/rbac-repository.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/modules/rbac/rbac.repository.ts`**

```ts
export type RoleRecord = { id: string; appServiceId: string; name: string }
export type PermissionRecord = { id: string; appServiceId: string; key: string }

export type RbacRepository = {
  createRole(r: RoleRecord): Promise<RoleRecord>
  createPermission(p: PermissionRecord): Promise<PermissionRecord>
  grantPermissionToRole(roleId: string, permissionId: string): Promise<void>
  assignRoleToUser(userId: string, roleId: string): Promise<void>
  findRoleById(id: string): Promise<RoleRecord | null>
  permissionsForUserInService(
    userId: string,
    appServiceId: string,
  ): Promise<string[]>
}

// In-memory test double. Mirror behavior in rbac.repository.drizzle.ts.
export function createInMemoryRbacRepository(): RbacRepository {
  const roles = new Map<string, RoleRecord>()
  const perms = new Map<string, PermissionRecord>()
  const rolePerms = new Set<string>() // `${roleId}:${permissionId}`
  const userRoleIds = new Map<string, Set<string>>() // userId -> roleIds

  return {
    createRole(r) {
      roles.set(r.id, { ...r })
      return Promise.resolve({ ...r })
    },
    createPermission(p) {
      perms.set(p.id, { ...p })
      return Promise.resolve({ ...p })
    },
    grantPermissionToRole(roleId, permissionId) {
      rolePerms.add(`${roleId}:${permissionId}`)
      return Promise.resolve()
    },
    assignRoleToUser(userId, roleId) {
      const set = userRoleIds.get(userId) ?? new Set()
      set.add(roleId)
      userRoleIds.set(userId, set)
      return Promise.resolve()
    },
    findRoleById(id) {
      return Promise.resolve(roles.has(id) ? { ...roles.get(id)! } : null)
    },
    permissionsForUserInService(userId, appServiceId) {
      const out = new Set<string>()
      for (const roleId of userRoleIds.get(userId) ?? []) {
        const role = roles.get(roleId)
        if (!role || role.appServiceId !== appServiceId) continue
        for (const p of perms.values()) {
          if (rolePerms.has(`${roleId}:${p.id}`)) out.add(p.key)
        }
      }
      return Promise.resolve([...out])
    },
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `deno test -A tests/unit/rbac-repository.test.ts`
Expected: PASS.

- [ ] **Step 5: Implement `src/modules/rbac/rbac.repository.drizzle.ts`**

```ts
import { and, eq, inArray } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import {
  permissions,
  rolePermissions,
  roles,
  userRoles,
} from '../../db/schema.ts'
import type { RbacRepository } from './rbac.repository.ts'

export function createDrizzleRbacRepository(db: Database): RbacRepository {
  return {
    async createRole(r) {
      await db.insert(roles).values(r)
      return r
    },
    async createPermission(p) {
      await db.insert(permissions).values(p)
      return p
    },
    async grantPermissionToRole(roleId, permissionId) {
      await db.insert(rolePermissions).values({ roleId, permissionId })
        .onDuplicateKeyUpdate({ set: { roleId } })
    },
    async assignRoleToUser(userId, roleId) {
      await db.insert(userRoles).values({ userId, roleId })
        .onDuplicateKeyUpdate({ set: { userId } })
    },
    async findRoleById(id) {
      const row = await db.query.roles.findFirst({ where: eq(roles.id, id) })
      return row ?? null
    },
    async permissionsForUserInService(userId, appServiceId) {
      const roleRows = await db.select({ id: roles.id })
        .from(userRoles)
        .innerJoin(roles, eq(userRoles.roleId, roles.id))
        .where(
          and(
            eq(userRoles.userId, userId),
            eq(roles.appServiceId, appServiceId),
          ),
        )
      const roleIds = roleRows.map((r) => r.id)
      if (!roleIds.length) return []
      const permRows = await db.select({ key: permissions.key })
        .from(rolePermissions)
        .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
        .where(inArray(rolePermissions.roleId, roleIds))
      return [...new Set(permRows.map((p) => p.key))]
    },
  }
}
```

- [ ] **Step 6: Type-check and commit**

Run: `deno check src/ tests/`
Expected: PASS.
```bash
git add -A && git commit -m "feat: per-service RBAC repository"
```

---

### Task 6: Audience-scoped token issuance

Wire orgs + RBAC into the grant flow: `POST /oauth/token` takes an `audience`, the server checks membership, resolves the user's permissions in that service, and mints a token carrying `aud`, `org`, `scope`, `client_id`. Refresh re-issues for the same audience.

**Files:**
- Modify: `src/lib/jwt.ts`, `src/modules/auth/auth.schema.ts`, `src/modules/auth/auth.service.ts`, `src/modules/auth/auth.routes.ts`, `src/modules/auth/token.repository.ts` (+ `.drizzle.ts`), `src/deps.ts`, `tests/helpers.ts`
- Test: `tests/unit/auth-service.test.ts` (extend), `tests/integration/auth.test.ts` (extend)

**Interfaces:**
- Produces:
  - `type AccessClaims = AccessPayload & { aud: string; org: string; scope: string; client_id: string }`
  - `signAccessToken` gains `aud`, `org`, `scope`, `clientId` options.
  - `authService.passwordGrant(email, password, audience)`, `authService.refreshGrant(refreshToken)` (audience read from the stored token's `appServiceId`).
  - `NewRefreshToken` gains `appServiceId: string`.
- Consumes: `OrgRepository`, `RbacRepository` (added to `createAuthService` deps and `createDeps`).

- [ ] **Step 1: Extend the JWT claims (write failing test)**

Add to `tests/unit/jwt.test.ts`:
```ts
Deno.test('access token carries aud, org, scope', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'iss',
    privateKeyPem,
    kid: 'k1',
    ttlSeconds: 900,
    aud: 'acme-billing',
    org: 'o1',
    scope: 'billing:read billing:write',
    clientId: 'cid_1',
  })
  const p = await verifyAccessToken(token, publicKeyPem)
  assertEquals(p.aud, 'acme-billing')
  assertEquals(p.org, 'o1')
  assertEquals(p.scope, 'billing:read billing:write')
  assertEquals(p.client_id, 'cid_1')
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `deno test -A tests/unit/jwt.test.ts`
Expected: FAIL — `signAccessToken` rejects the extra options / `aud` undefined.

- [ ] **Step 3: Extend `src/lib/jwt.ts`**

Replace the `AccessPayload` type and `signAccessToken` with:
```ts
export type AccessPayload = { iss: string; sub: string; iat: number; exp: number }
export type AccessClaims = AccessPayload & {
  aud: string
  org: string
  scope: string
  client_id: string
}

export async function signAccessToken(
  opts: {
    sub: string
    issuer: string
    privateKeyPem: string
    kid: string
    ttlSeconds: number
    aud: string
    org: string
    scope: string
    clientId: string
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: opts.issuer,
    sub: opts.sub,
    aud: opts.aud,
    org: opts.org,
    scope: opts.scope,
    client_id: opts.clientId,
    iat: now,
    exp: now + opts.ttlSeconds,
  }
  return await sign(payload, opts.privateKeyPem, 'RS256')
}
```
Change `verifyAccessToken`'s return type to `AccessClaims`:
```ts
export async function verifyAccessToken(
  token: string,
  publicKeyPem: string,
): Promise<AccessClaims> {
  return await verify(token, publicKeyPem, 'RS256') as AccessClaims
}
```

- [ ] **Step 4: Run the jwt test to verify it passes**

Run: `deno test -A tests/unit/jwt.test.ts`
Expected: PASS.

- [ ] **Step 5: Add `audience` to the password grant schema (`src/modules/auth/auth.schema.ts`)**

In the `password` member of the discriminated union, add `audience: z.string().min(1)`:
```ts
  z.object({
    grant_type: z.literal('password'),
    username: z.string().email(),
    password: z.string().min(1),
    audience: z.string().min(1),
  }),
```

- [ ] **Step 6: Add `appServiceId` to refresh-token records**

In `src/modules/auth/token.repository.ts`, add `appServiceId: string` to `RefreshTokenRecord` and include it in `NewRefreshToken`'s `Pick`:
```ts
export type NewRefreshToken = Pick<
  RefreshTokenRecord,
  'id' | 'userId' | 'appServiceId' | 'tokenHash' | 'expiresAt'
>
```
The in-memory fake already spreads `...token`, so it carries `appServiceId` automatically.
In `src/modules/auth/token.repository.drizzle.ts`, no change needed — `create`/`rotate` already spread `...token`/`...next` into `values`.

- [ ] **Step 7: Extend `createAuthService` deps and the grant logic (`src/modules/auth/auth.service.ts`)**

Add imports:
```ts
import type { OrgRepository } from '../orgs/orgs.repository.ts'
import type { RbacRepository } from '../rbac/rbac.repository.ts'
```
Add `orgRepo: OrgRepository` and `rbacRepo: RbacRepository` to the `createAuthService` deps param and destructure them.
Replace `issueTokens` with an audience-aware version:
```ts
  async function issueTokensForService(
    userId: string,
    audience: string,
  ): Promise<TokenPair> {
    const service = await orgRepo.findServiceByAudience(audience)
    if (!service) throw AppError.badRequest('unknown audience')
    if (!(await orgRepo.isMember(userId, service.orgId))) {
      throw AppError.forbidden('not a member of this organization')
    }
    const scopes = await rbacRepo.permissionsForUserInService(userId, service.id)
    const access_token = await signAccessToken({
      sub: userId,
      issuer: config.issuer,
      privateKeyPem: keySet.privateKeyPem,
      kid: keySet.kid,
      ttlSeconds: config.accessTokenTtl,
      aud: service.audience,
      org: service.orgId,
      scope: scopes.join(' '),
      clientId: service.clientId,
    })
    const refresh = generateRefreshToken()
    await tokenRepo.create({
      id: crypto.randomUUID(),
      userId,
      appServiceId: service.id,
      tokenHash: await hashToken(refresh),
      expiresAt: new Date(Date.now() + config.refreshTokenTtl * 1000),
    })
    return {
      access_token,
      refresh_token: refresh,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtl,
    }
  }
```
Update `passwordGrant` to take `audience` and call the new function:
```ts
    async passwordGrant(
      email: string,
      password: string,
      audience: string,
    ): Promise<TokenPair> {
      const user = await userRepo.findByEmail(email)
      const hash = user?.passwordHash ?? await getDummyHash()
      const passwordOk = await verifyPassword(password, hash)
      if (!user || !user.passwordHash || !passwordOk) {
        throw AppError.unauthorized('invalid credentials')
      }
      return issueTokensForService(user.id, audience)
    },
```
Update `refreshGrant` to re-issue for the stored token's service. Replace its token-minting block so that, after validating `existing`, it resolves the service by `existing.appServiceId` and re-runs the scope/sign logic. Concretely, replace the body after the reuse/expiry checks with:
```ts
      const service = await orgRepo.findServiceById(existing.appServiceId)
      if (!service) throw AppError.unauthorized('invalid refresh token')
      const scopes = await rbacRepo.permissionsForUserInService(
        existing.userId,
        service.id,
      )
      const refresh = generateRefreshToken()
      const next: NewRefreshToken = {
        id: crypto.randomUUID(),
        userId: existing.userId,
        appServiceId: service.id,
        tokenHash: await hashToken(refresh),
        expiresAt: new Date(Date.now() + config.refreshTokenTtl * 1000),
      }
      const access_token = await signAccessToken({
        sub: existing.userId,
        issuer: config.issuer,
        privateKeyPem: keySet.privateKeyPem,
        kid: keySet.kid,
        ttlSeconds: config.accessTokenTtl,
        aud: service.audience,
        org: service.orgId,
        scope: scopes.join(' '),
        clientId: service.clientId,
      })
      if (!(await tokenRepo.rotate(existing.id, next))) {
        await tokenRepo.revokeAllForUser(existing.userId)
        throw AppError.unauthorized('refresh token reuse detected')
      }
      return {
        access_token,
        refresh_token: refresh,
        token_type: 'Bearer',
        expires_in: config.accessTokenTtl,
      }
```
Replace the old `issueTokens` references: `loginWithGoogle` previously called `issueTokens(userId)`. Google login now needs an audience too; for Phase 1, give it the same `audience` requirement by reading it from a query param in the route (Step 9). Update `loginWithGoogle` signature to `(profile, audience: string)` and call `issueTokensForService(user.id, audience)` / `issueTokensForService(existing.userId, audience)`. Keep `resolveUser` unchanged.

- [ ] **Step 8: Wire the new repos into `createDeps` and `tests/helpers.ts`**

In `src/deps.ts`, construct `const orgRepo = createDrizzleOrgRepository(db)` and `const rbacRepo = createDrizzleRbacRepository(db)` (add imports), and pass `orgRepo, rbacRepo` into `createAuthService({ ... })`.
In `tests/helpers.ts`, build `const orgRepo = createInMemoryOrgRepository()` and `const rbacRepo = createInMemoryRbacRepository()` (add imports), pass them into `createAuthService`, and **return them from `makeTestDeps`/`makeTestApp`** so tests can seed orgs/services/members:
```ts
  return { app: createApp(deps), userRepo, orgRepo, rbacRepo }
```

- [ ] **Step 9: Update `POST /oauth/token` and Google routes (`src/modules/auth/auth.routes.ts`)**

The `/token` handler's password branch now passes audience:
```ts
      const pair = body.grant_type === 'password'
        ? await svc.passwordGrant(body.username, body.password, body.audience)
        : await svc.refreshGrant(body.refresh_token)
```
For `/google`, read `audience` from the query string and pass it:
```ts
      const audience = c.req.query('audience')
      if (!audience) {
        return c.json(
          { error: { code: 'bad_request', message: 'audience required' } },
          400,
        )
      }
      const pair = await c.var.authService.loginWithGoogle({ ... }, audience)
```

- [ ] **Step 10: Extend the auth-service unit test (failing → passing)**

Add to `tests/unit/auth-service.test.ts` a test that seeds an org/service/membership/role via the in-memory repos and asserts the password grant returns a token whose decoded `aud`/`scope` match. Build the service directly with in-memory repos:
```ts
import { decode } from 'hono/jwt'
// ... inside a Deno.test:
// create user (hash a password via lib/password), create org+service,
// addMember, create role+permission, grant + assign, then:
const pair = await authService.passwordGrant('a@b.com', 'pw123456', 'acme-billing')
const { payload } = decode(pair.access_token)
assertEquals(payload.aud, 'acme-billing')
assertEquals(payload.scope, 'billing:read')
```
(Use the existing test's construction style; reuse `createInMemoryOrgRepository`/`createInMemoryRbacRepository`.)

- [ ] **Step 11: Update the integration auth test**

In `tests/integration/auth.test.ts` (and the `authHeader` helper usage), seed an org + service + membership before requesting `/oauth/token`, and pass `audience` in the request body. Update `authHeader` in `tests/helpers.ts` to accept and send an `audience` argument:
```ts
export async function authHeader(
  app: ReturnType<typeof createApp>,
  email: string,
  password: string,
  audience: string,
) {
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'password', username: email, password, audience }),
  })
  // ... unchanged
}
```
Update every existing caller of `authHeader` to pass a seeded audience.

- [ ] **Step 12: Run the full non-DB suite**

Run: `deno task test:unit && deno task test:integration && deno task check:all`
Expected: PASS. Fix any remaining `authHeader`/`issueTokens` call-site breakages until green.

- [ ] **Step 13: Commit**

```bash
git add -A && git commit -m "feat: audience-scoped token issuance with per-service scopes"
```

---

### Task 7: Management API + token-scoped authorization

Add admin endpoints to create orgs, register app services (returning a one-time client secret), manage members, and define per-service RBAC. Protect them with the existing `requireAuth`/`requirePermission`, but resolve the caller's permissions from the **token's `scope` claim** (the token was minted for the reserved `platform` service in Task 8).

**Files:**
- Modify: `src/middleware/auth.ts`, `src/types.ts`, `src/modules/users/users.routes.ts` (only if it reads `user.roles`)
- Create: `src/modules/admin/admin.service.ts`, `src/modules/admin/admin.routes.ts`, `src/modules/admin/admin.schema.ts`
- Modify: `src/deps.ts`, `src/app.ts`, `tests/helpers.ts`
- Test: `tests/integration/admin.test.ts`

**Interfaces:**
- Produces:
  - `AuthenticatedUser = { id: string; email: string; permissions: string[]; org: string; aud: string }`
  - `AdminService` with: `createOrg`, `listOrgs`, `getOrg`, `registerService` (returns `{ service, clientSecret }`), `listServices`, `addMember`, `removeMember`, `createRole`, `createPermission`, `grantPermission`, `assignRole`.
  - Admin routes (all under the app root; see Step 6).
- Consumes: `OrgRepository`, `RbacRepository`, `UserRepository`, `verifyAccessToken`.

- [ ] **Step 1: Update `AuthenticatedUser` and `requireAuth` to read permissions from the token (failing test)**

Write `tests/integration/admin.test.ts` first (it will drive everything). Minimum first case:
```ts
import { assert, assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'
import { seedPlatformAdmin } from '../helpers.ts'

Deno.test('admin can create an org', async () => {
  const ctx = makeTestApp()
  const token = await seedPlatformAdmin(ctx) // returns a platform access token w/ orgs:write
  const res = await ctx.app.request('/orgs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ slug: 'acme', name: 'Acme' }),
  })
  assertEquals(res.status, 201)
  const body = await res.json()
  assertEquals(body.slug, 'acme')
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `deno test -A tests/integration/admin.test.ts`
Expected: FAIL — `seedPlatformAdmin` and `/orgs` don't exist.

- [ ] **Step 3: Update `src/types.ts` and `src/middleware/auth.ts`**

`src/types.ts`:
```ts
export type AuthenticatedUser = {
  id: string
  email: string
  permissions: string[]
  org: string
  aud: string
}
```
`src/middleware/auth.ts` — verify, then build the user from claims (permissions from `scope`), fetching email lazily:
```ts
  let claims
  try {
    claims = await verifyAccessToken(token, c.var.keySet.publicKeyPem)
  } catch {
    throw AppError.unauthorized('invalid token')
  }
  const user = await c.var.userService.get(claims.sub).catch(() => null)
  c.set('user', {
    id: claims.sub,
    email: user?.email ?? '',
    permissions: claims.scope ? claims.scope.split(' ') : [],
    org: claims.org,
    aud: claims.aud,
  })
  await next()
```
If `userService.get` does not exist, use `c.var.authService.resolveUser(claims.sub)` for `{ email }` instead, wrapped in `.catch(() => null)`. Remove the now-unused `resolveUser` permission fields usage. Check `src/modules/users/users.routes.ts` for any `user.roles` reference and drop it (the `/users/me` handler should return `c.var.user` as-is).

- [ ] **Step 4: Implement `src/modules/admin/admin.schema.ts`**

```ts
import { z } from 'zod'

export const createOrgSchema = z.object({
  slug: z.string().min(1).max(64),
  name: z.string().min(1).max(255),
})

export const registerServiceSchema = z.object({
  slug: z.string().min(1).max(64),
  name: z.string().min(1).max(255),
  audience: z.string().min(1).max(128),
  type: z.enum(['public', 'confidential']),
  redirectUris: z.array(z.string().url()).default([]),
})

export const addMemberSchema = z.object({ userId: z.string().min(1) })
export const createRoleSchema = z.object({ name: z.string().min(1).max(64) })
export const createPermissionSchema = z.object({ key: z.string().min(1).max(64) })
export const grantPermissionSchema = z.object({ permissionId: z.string().min(1) })
export const assignRoleSchema = z.object({ roleId: z.string().min(1) })
```

- [ ] **Step 5: Implement `src/modules/admin/admin.service.ts`**

```ts
import type { OrgRepository } from '../orgs/orgs.repository.ts'
import type { RbacRepository } from '../rbac/rbac.repository.ts'
import { generateRefreshToken, hashToken } from '../../lib/tokens.ts'
import { AppError } from '../../lib/errors.ts'

export type AdminService = ReturnType<typeof createAdminService>

export function createAdminService(deps: {
  orgRepo: OrgRepository
  rbacRepo: RbacRepository
}) {
  const { orgRepo, rbacRepo } = deps

  async function requireService(id: string) {
    const s = await orgRepo.findServiceById(id)
    if (!s) throw AppError.notFound('service not found')
    return s
  }

  return {
    async createOrg(input: { slug: string; name: string }) {
      return await orgRepo.createOrg({
        id: crypto.randomUUID(),
        slug: input.slug,
        name: input.name,
        createdAt: new Date(),
      })
    },
    listOrgs: () => orgRepo.listOrgs(),
    async getOrg(id: string) {
      const o = await orgRepo.findOrgById(id)
      if (!o) throw AppError.notFound('org not found')
      return o
    },
    async registerService(orgId: string, input: {
      slug: string
      name: string
      audience: string
      type: 'public' | 'confidential'
      redirectUris: string[]
    }) {
      if (!(await orgRepo.findOrgById(orgId))) {
        throw AppError.notFound('org not found')
      }
      const clientId = `cid_${generateRefreshToken().slice(0, 24)}`
      // Confidential clients get a secret; returned once, stored hashed.
      const clientSecret = input.type === 'confidential'
        ? generateRefreshToken()
        : null
      const service = await orgRepo.createService({
        id: crypto.randomUUID(),
        orgId,
        clientId,
        clientSecretHash: clientSecret ? await hashToken(clientSecret) : null,
        name: input.name,
        slug: input.slug,
        audience: input.audience,
        type: input.type,
        redirectUris: input.redirectUris,
        createdAt: new Date(),
      })
      return { service, clientSecret }
    },
    listServices: (orgId: string) => orgRepo.listServicesByOrg(orgId),
    async addMember(orgId: string, userId: string) {
      if (!(await orgRepo.findOrgById(orgId))) {
        throw AppError.notFound('org not found')
      }
      await orgRepo.addMember({
        id: crypto.randomUUID(),
        userId,
        orgId,
        createdAt: new Date(),
      })
    },
    removeMember: (orgId: string, userId: string) =>
      orgRepo.removeMember(userId, orgId),
    async createRole(serviceId: string, name: string) {
      await requireService(serviceId)
      return await rbacRepo.createRole({
        id: crypto.randomUUID(),
        appServiceId: serviceId,
        name,
      })
    },
    async createPermission(serviceId: string, key: string) {
      await requireService(serviceId)
      return await rbacRepo.createPermission({
        id: crypto.randomUUID(),
        appServiceId: serviceId,
        key,
      })
    },
    grantPermission: (roleId: string, permissionId: string) =>
      rbacRepo.grantPermissionToRole(roleId, permissionId),
    assignRole: (userId: string, roleId: string) =>
      rbacRepo.assignRoleToUser(userId, roleId),
  }
}
```

- [ ] **Step 6: Implement `src/modules/admin/admin.routes.ts`**

```ts
import { Hono } from 'hono'
import { validator } from 'hono-openapi/zod'
import type { AppEnv } from '../../deps.ts'
import { requireAuth } from '../../middleware/auth.ts'
import { requirePermission } from '../../middleware/authorize.ts'
import {
  addMemberSchema,
  assignRoleSchema,
  createOrgSchema,
  createPermissionSchema,
  createRoleSchema,
  grantPermissionSchema,
  registerServiceSchema,
} from './admin.schema.ts'

const admin = new Hono<AppEnv>()
  .use('*', requireAuth)
  .post('/orgs', requirePermission('orgs:write'), validator('json', createOrgSchema), async (c) => {
    return c.json(await c.var.adminService.createOrg(c.req.valid('json')), 201)
  })
  .get('/orgs', requirePermission('orgs:read'), async (c) => {
    return c.json(await c.var.adminService.listOrgs())
  })
  .get('/orgs/:id', requirePermission('orgs:read'), async (c) => {
    return c.json(await c.var.adminService.getOrg(c.req.param('id')))
  })
  .post('/orgs/:id/services', requirePermission('services:write'), validator('json', registerServiceSchema), async (c) => {
    return c.json(
      await c.var.adminService.registerService(c.req.param('id'), c.req.valid('json')),
      201,
    )
  })
  .get('/orgs/:id/services', requirePermission('services:read'), async (c) => {
    return c.json(await c.var.adminService.listServices(c.req.param('id')))
  })
  .post('/orgs/:id/members', requirePermission('members:write'), validator('json', addMemberSchema), async (c) => {
    await c.var.adminService.addMember(c.req.param('id'), c.req.valid('json').userId)
    return c.body(null, 204)
  })
  .delete('/orgs/:id/members/:userId', requirePermission('members:write'), async (c) => {
    await c.var.adminService.removeMember(c.req.param('id'), c.req.param('userId'))
    return c.body(null, 204)
  })
  .post('/services/:id/roles', requirePermission('rbac:write'), validator('json', createRoleSchema), async (c) => {
    return c.json(await c.var.adminService.createRole(c.req.param('id'), c.req.valid('json').name), 201)
  })
  .post('/services/:id/permissions', requirePermission('rbac:write'), validator('json', createPermissionSchema), async (c) => {
    return c.json(await c.var.adminService.createPermission(c.req.param('id'), c.req.valid('json').key), 201)
  })
  .post('/roles/:id/permissions', requirePermission('rbac:write'), validator('json', grantPermissionSchema), async (c) => {
    await c.var.adminService.grantPermission(c.req.param('id'), c.req.valid('json').permissionId)
    return c.body(null, 204)
  })
  .post('/users/:userId/roles', requirePermission('rbac:write'), validator('json', assignRoleSchema), async (c) => {
    await c.var.adminService.assignRole(c.req.param('userId'), c.req.valid('json').roleId)
    return c.body(null, 204)
  })

export default admin
```

- [ ] **Step 7: Wire `adminService` into deps and mount the routes**

In `src/deps.ts`: add `import { createAdminService, type AdminService } from './modules/admin/admin.service.ts'`, add `adminService: AdminService` to `Deps`, construct `createAdminService({ orgRepo, rbacRepo })`, and include it in the returned object. (`orgRepo`/`rbacRepo` already exist from Task 6.)
In `src/app.ts`: `import admin from './modules/admin/admin.routes.ts'` and add `.route('/', admin)` after the other routes.
In `tests/helpers.ts`: add `adminService: createAdminService({ orgRepo, rbacRepo })` to the test `deps`.

- [ ] **Step 8: Add the `seedPlatformAdmin` test helper**

In `tests/helpers.ts`, add a helper that seeds the reserved platform service, a user with all platform permissions, membership, and returns a signed access token:
```ts
import { signAccessToken } from '../src/lib/jwt.ts'

export const PLATFORM_PERMISSIONS = [
  'orgs:read', 'orgs:write', 'services:read', 'services:write',
  'members:write', 'rbac:write',
]

export async function seedPlatformAdmin(ctx: ReturnType<typeof makeTestApp>) {
  const { orgRepo } = ctx as unknown as { orgRepo: ReturnType<typeof createInMemoryOrgRepository> }
  // Mint a platform-scoped token directly (the token's scope IS the authz).
  return await signAccessToken({
    sub: 'admin-user',
    issuer: 'http://test.local',
    privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'platform',
    org: 'platform',
    scope: PLATFORM_PERMISSIONS.join(' '),
    clientId: 'platform',
  })
}
```
(`makeTestApp` must return `orgRepo`/`rbacRepo`/`app` — ensured in Task 6 Step 8. Adjust the destructure to match the actual returned shape.)

- [ ] **Step 9: Flesh out `tests/integration/admin.test.ts`**

Cover, at minimum: create org (201), missing-permission token → 403, register confidential service returns a one-time `clientSecret`, add member, and an end-to-end RBAC grant (create role + permission, grant, assign to a user, then password-grant that user for the service and assert the scope claim contains the permission). Use `seedPlatformAdmin` for the admin token.

- [ ] **Step 10: Run the suite**

Run: `deno task test:unit && deno task test:integration && deno task check:all`
Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add -A && git commit -m "feat: management API for orgs, services, members, and RBAC"
```

---

### Task 8: Seed the platform org/service + docs

Bootstrap a reserved `platform` org + app service whose roles/permissions gate the management API, so a real deployment has an admin to start from. Update env docs.

**Files:**
- Modify: `src/db/rbac-constants.ts`, `src/db/seed.ts`, `.env.example`, `README.md`
- Test: none (seed is idempotent; covered by e2e if run)

**Interfaces:**
- Produces: seeded `platform` org, `platform` app service (`audience='platform'`), `admin` role with all platform permissions, and a bootstrap admin user from env.
- Consumes: `organizations`, `appServices`, `memberships`, `roles`, `permissions`, `rolePermissions`, `userRoles`, `users`.

- [ ] **Step 1: Replace `src/db/rbac-constants.ts` with platform constants**

```ts
export const PLATFORM_ORG_SLUG = 'platform'
export const PLATFORM_AUDIENCE = 'platform'
export const PLATFORM_CLIENT_ID = 'platform'

export const PLATFORM_PERMISSIONS = [
  'orgs:read',
  'orgs:write',
  'services:read',
  'services:write',
  'members:write',
  'rbac:write',
] as const

export const ROLE_ADMIN = 'admin'
```

- [ ] **Step 2: Rewrite `src/db/seed.ts` to seed the platform tenant + bootstrap admin**

Build an idempotent seed that: find-or-creates the platform org and app service, the `admin` role + platform permissions (all scoped to the platform service), grants every permission to `admin`, and — if `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` env are set — find-or-creates that user, makes them a platform member, and assigns the `admin` role. Use the existing find-or-insert pattern (`db.query.*.findFirst` then `insert`). Hash the admin password with `hashPassword` from `src/lib/password.ts`. Print the created `client_id` on completion.

Reference shape (fill in find-or-insert per row, mirroring the original seed's style):
```ts
// 1. org (slug = PLATFORM_ORG_SLUG)
// 2. app_service (audience = PLATFORM_AUDIENCE, client_id = PLATFORM_CLIENT_ID, type 'confidential')
// 3. permissions: one row per PLATFORM_PERMISSIONS, app_service_id = platform service id
// 4. role 'admin' for the platform service; grant all platform permissions
// 5. if BOOTSTRAP_ADMIN_EMAIL set: user (hashed pw), membership, user_roles(admin)
```

- [ ] **Step 3: Add new env vars to `.env.example`**

Replace `JWT_SECRET=...` with:
```
# RSA keypair (PEM). Generate with: deno task keys:gen
JWT_PRIVATE_KEY=
JWT_PUBLIC_KEY=
JWT_ISSUER=http://localhost:3000
# Optional bootstrap admin seeded by `deno task db:seed`
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=change-me-please
```

- [ ] **Step 4: Add a `keys:gen` task to generate a keypair**

In `deno.json` tasks, add:
```json
    "keys:gen": "deno eval \"import { generateRsaKeyPairPem } from './src/lib/keys.ts'; const k = await generateRsaKeyPairPem(); console.log('JWT_PRIVATE_KEY=\\\"'+k.privateKeyPem.replace(/\\n/g,'\\\\n')+'\\\"'); console.log('JWT_PUBLIC_KEY=\\\"'+k.publicKeyPem.replace(/\\n/g,'\\\\n')+'\\\"')\""
```
(Outputs the two PEM env lines with escaped newlines, ready to paste into `.env`.)

- [ ] **Step 5: Update `README.md`**

Document: the new `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`/`JWT_ISSUER` env vars and `deno task keys:gen`; the JWKS + discovery endpoints; the `audience` parameter on `POST /oauth/token`; the management API endpoints (orgs/services/members/RBAC); and the `BOOTSTRAP_ADMIN_*` seed behavior. Remove `JWT_SECRET` references.

- [ ] **Step 6: Verify it all type-checks and tests pass**

Run: `deno task check:all && deno task test:unit && deno task test:integration`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: seed platform tenant + bootstrap admin, update docs"
```

---

## Self-Review

**Spec coverage:**
- JWKS + RS256 → Tasks 1, 2. ✓
- Multi-org + memberships → Tasks 3, 4. ✓
- Per-service RBAC → Tasks 3, 5; resolution used in Task 6. ✓
- Audience-scoped password/refresh grant → Task 6. ✓
- Management API (orgs/services/members/RBAC) → Task 7. ✓
- Seed platform tenant → Task 8. ✓
- Testing layers (unit/integration/e2e) → each task adds unit/integration; Drizzle adapters built for e2e. ✓
- M2M / auth-code SSO → correctly **out of this plan** (Phase 2/3, separate plans). ✓

**Deferred / follow-ups (not Phase 1):**
- `kid` is published in JWKS but not yet written into the JWT header (single-key, so verification succeeds without it). Wire the header when key rotation lands (Phase 3).
- e2e tests for the new Drizzle repos (orgs, rbac) can be added mirroring `tests/e2e/users-repository.drizzle.test.ts`; not required for the in-memory-backed integration suite to pass.

**Known follow-up for the implementer:** several tasks edit shared wiring (`deps.ts`, `tests/helpers.ts`, `auth.routes.ts`). When a step says "update every caller," run `deno task check:all` to surface the exact call sites — the type-checker is the checklist.
