import { assertEquals, assertRejects } from '@std/assert'
import { ciEquals } from '../../src/lib/inmemory.ts'
import { createInMemoryOrgRepository } from '../../src/modules/orgs/orgs.repository.ts'
import { createInMemoryRbacRepository } from '../../src/modules/rbac/rbac.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../../src/modules/auth/token.repository.ts'
import { createInMemorySessionRepository } from '../../src/modules/auth/session.repository.ts'
import { createInMemoryAuthCodeRepository } from '../../src/modules/auth/authcode.repository.ts'
import { createInMemoryVerificationTokenRepository } from '../../src/modules/verification/verification.repository.ts'
import { createInMemorySocialAccountRepository } from '../../src/modules/auth/social.repository.ts'

// One test per table, asserting the constraints MySQL has and a Map does not:
// the PRIMARY key, the UNIQUE indexes, and the fact that every char column is
// utf8mb4_0900_ai_ci so those indexes collapse case. A double that accepts
// what the driver rejects lets the suite prove behaviour the database would
// never allow -- see the email-change bug for what that costs.
//
// The join tables (role_permissions, user_roles, client_roles, memberships)
// are deliberately NOT here: their writers use onDuplicateKeyUpdate, so a
// repeat is a no-op on both sides and making the doubles throw would be wrong.

const now = new Date()

Deno.test('in-memory org repo enforces organizations and app_services constraints', async () => {
  const repo = createInMemoryOrgRepository()
  const org = { id: 'o1', slug: 'acme', name: 'Acme', createdAt: now }
  await repo.createOrg(org)

  await assertRejects(
    () => repo.createOrg({ ...org, slug: 'other' }),
    Error,
    'duplicate organizations.PRIMARY',
  )
  await assertRejects(
    () => repo.createOrg({ ...org, id: 'o2', slug: 'ACME' }),
    Error,
    'duplicate organizations.slug',
  )
  assertEquals((await repo.findOrgBySlug('ACME'))?.id, 'o1')

  const svc = {
    id: 's1',
    orgId: 'o1',
    clientId: 'cid_1',
    clientSecretHash: null,
    name: 'App',
    slug: 'app',
    audience: 'acme-app',
    type: 'public' as const,
    redirectUris: [],
    createdAt: now,
  }
  await repo.createService(svc)
  await assertRejects(
    () => repo.createService({ ...svc, clientId: 'cid_2', audience: 'x' }),
    Error,
    'duplicate app_services.PRIMARY',
  )
  await assertRejects(
    () => repo.createService({ ...svc, id: 's2', audience: 'x' }),
    Error,
    'duplicate app_services.client_id',
  )
  await assertRejects(
    () =>
      repo.createService({
        ...svc,
        id: 's2',
        clientId: 'cid_2',
        audience: 'ACME-APP',
      }),
    Error,
    'duplicate app_services.audience',
  )
  assertEquals((await repo.findServiceByAudience('ACME-APP'))?.id, 's1')
  assertEquals((await repo.findServiceByClientId('CID_1'))?.id, 's1')

  // memberships is written with onDuplicateKeyUpdate, so a repeat is a no-op.
  await repo.addMember({ id: 'm1', userId: 'u1', orgId: 'o1', createdAt: now })
  await repo.addMember({ id: 'm2', userId: 'u1', orgId: 'o1', createdAt: now })
  assertEquals(await repo.isMember('u1', 'o1'), true)
})

Deno.test('in-memory rbac repo enforces the per-service UNIQUE indexes', async () => {
  const repo = createInMemoryRbacRepository()
  await repo.createRole({ id: 'r1', appServiceId: 'svc1', name: 'editor' })
  await repo.createPermission({ id: 'p1', appServiceId: 'svc1', key: 'd:read' })

  await assertRejects(
    () => repo.createRole({ id: 'r1', appServiceId: 'svc2', name: 'other' }),
    Error,
    'duplicate roles.PRIMARY',
  )
  await assertRejects(
    () => repo.createRole({ id: 'r2', appServiceId: 'svc1', name: 'Editor' }),
    Error,
    'duplicate roles.app_service_id_name',
  )
  await assertRejects(
    () =>
      repo.createPermission({ id: 'p2', appServiceId: 'svc1', key: 'D:Read' }),
    Error,
    'duplicate permissions.app_service_id_key',
  )

  // The constraint is (app_service_id, name), not the name alone: per-service
  // RBAC depends on two services reusing a name.
  await repo.createRole({ id: 'r3', appServiceId: 'svc2', name: 'editor' })
  await repo.createPermission({ id: 'p3', appServiceId: 'svc2', key: 'd:read' })
  assertEquals((await repo.findRoleByName('svc2', 'EDITOR'))?.id, 'r3')
  assertEquals((await repo.findPermissionByKey('svc1', 'D:READ'))?.id, 'p1')

  // Join tables use onDuplicateKeyUpdate -- repeats must stay no-ops.
  await repo.grantPermissionToRole('r1', 'p1')
  await repo.grantPermissionToRole('r1', 'p1')
  await repo.assignRoleToUser('u1', 'r1')
  await repo.assignRoleToUser('u1', 'r1')
  assertEquals(await repo.permissionsForUserInService('u1', 'svc1'), ['d:read'])
})

Deno.test('in-memory token, session, authcode and verification repos enforce their UNIQUE hash', async () => {
  const expiresAt = new Date(Date.now() + 60_000)

  const tokens = createInMemoryRefreshTokenRepository()
  const token = {
    id: 't1',
    userId: 'u1',
    appServiceId: 's1',
    tokenHash: 'hash1',
    expiresAt,
  }
  await tokens.create(token)
  await assertRejects(
    () => tokens.create({ ...token, tokenHash: 'other' }),
    Error,
    'duplicate refresh_tokens.PRIMARY',
  )
  await assertRejects(
    () => tokens.create({ ...token, id: 't2' }),
    Error,
    'duplicate refresh_tokens.token_hash',
  )
  // rotate() inserts too, so it is subject to the same index.
  await assertRejects(
    () => tokens.rotate('t1', { ...token, id: 't3' }),
    Error,
    'duplicate refresh_tokens.token_hash',
  )

  const sessions = createInMemorySessionRepository()
  const session = { id: 'x1', userId: 'u1', tokenHash: 'shash', expiresAt }
  await sessions.create(session)
  await assertRejects(
    () => sessions.create({ ...session, id: 'x2' }),
    Error,
    'duplicate sessions.token_hash',
  )

  const codes = createInMemoryAuthCodeRepository()
  const code = {
    id: 'c1',
    codeHash: 'chash',
    userId: 'u1',
    appServiceId: 's1',
    redirectUri: 'https://a/cb',
    codeChallenge: 'cc',
    codeChallengeMethod: 'S256',
    scope: 'openid',
    nonce: null,
    authTime: now,
    expiresAt,
  }
  await codes.create(code)
  await assertRejects(
    () => codes.create({ ...code, id: 'c2' }),
    Error,
    'duplicate authorization_codes.code_hash',
  )

  const verifications = createInMemoryVerificationTokenRepository()
  const vt = {
    id: 'v1',
    userId: 'u1',
    email: 'a@b.com',
    purpose: 'verify_email' as const,
    tokenHash: 'vhash',
    expiresAt,
  }
  await verifications.create(vt)
  await assertRejects(
    () => verifications.create({ ...vt, id: 'v2' }),
    Error,
    'duplicate email_verification_tokens.token_hash',
  )
})

// UNIQUE(provider, provider_account_id) is what atomically claims a Google
// account against a concurrent bind -- auth.service.ts says so at the call
// site. The Map overwrote instead, so in this mode the second caller silently
// took the identity: the exact opposite of the guarantee being relied on.
Deno.test('in-memory social repo refuses a second link of one provider account', async () => {
  const repo = createInMemorySocialAccountRepository()
  const link = {
    id: 'l1',
    userId: 'u1',
    provider: 'google',
    providerAccountId: 'sub-123',
  }
  await repo.link(link)

  await assertRejects(
    () => repo.link({ ...link, id: 'l2', userId: 'attacker' }),
    Error,
    'duplicate social_accounts.provider_provider_account_id',
  )
  assertEquals(
    (await repo.findByProviderAccount('google', 'sub-123'))?.userId,
    'u1',
  )
})

// Ground truth: each pair was run through MySQL as
//   SELECT (_utf8mb4'<a>' COLLATE utf8mb4_0900_ai_ci)
//        = (_utf8mb4'<b>' COLLATE utf8mb4_0900_ai_ci)
// against the same 8.x server the suite uses. ciEquals has to give the same
// answer, or the doubles disagree with the database about which rows exist.
//
// The EQ half is what a lowercase comparison gets wrong: primary strength
// folds accents, ligatures, full-width forms and kana, not just case. The NE
// half is the part that is easy to over-fold -- a dotless i is its own letter,
// and these collations are NO PAD, so a trailing space is significant.
const COLLATES_EQUAL: [string, string][] = [
  ['cafe', 'café'],
  ['o', 'ö'],
  ['e', 'É'],
  ['ss', 'ß'],
  ['straße', 'strasse'],
  ['ae', 'æ'],
  ['oe', 'œ'],
  ['dz', 'ǆ'],
  ['fi', 'ﬁ'],
  ['i', 'İ'],
  ['a', 'ａ'],
  ['user@b.com', 'ｕｓｅｒ@b.com'],
  ['あ', 'ア'],
  ['Ångström', 'angstrom'],
  ['a\u0301', 'á'],
  ['o', 'ø'],
  ['xii', 'Ⅻ'],
  ['hello', 'HELLO'],
]

const COLLATES_DIFFERENT: [string, string][] = [
  ['i', 'ı'], // dotless i is a distinct letter, not a case variant
  ['hello', 'hello '], // 0900 collations are NO PAD
  ['ab', 'a b'],
  ['a.b', 'ab'],
  ['x', 'χ'],
  ['v', 'w'],
  ['th', 'þ'], // thorn is its own letter at primary strength, not a ligature
  ['I', 'ı'],
]

Deno.test('ciEquals matches utf8mb4_0900_ai_ci on pairs verified against MySQL', () => {
  for (const [a, b] of COLLATES_EQUAL) {
    assertEquals(ciEquals(a, b), true, `${a} should collate equal to ${b}`)
    assertEquals(ciEquals(b, a), true, `${b} should collate equal to ${a}`)
  }
  for (const [a, b] of COLLATES_DIFFERENT) {
    assertEquals(ciEquals(a, b), false, `${a} should NOT collate equal to ${b}`)
    assertEquals(ciEquals(b, a), false, `${b} should NOT collate equal to ${a}`)
  }
  // NULL never equals anything, including another NULL -- MySQL's rule, and
  // what lets two address-less guests coexist under a UNIQUE index.
  assertEquals(ciEquals(null, null), false)
  assertEquals(ciEquals(undefined, 'a'), false)
  assertEquals(ciEquals('a', null), false)
})

// The collator follows its locale, and an unpinned one follows the machine's.
// 'tr' and 'sv' genuinely disagree with MySQL, so a laptop configured either
// way would run a different suite than CI. Note 'und' does NOT resolve to root.
Deno.test('the collation comparison does not depend on the machine locale', () => {
  assertEquals(
    new Intl.Collator('en', { sensitivity: 'base' }).resolvedOptions().locale,
    'en',
  )
  // The pair a pinned locale gets right and Turkish does not.
  assertEquals(ciEquals('i', 'İ'), true)
})
