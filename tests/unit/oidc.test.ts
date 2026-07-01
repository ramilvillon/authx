import { assertEquals } from '@std/assert'
import { claimsForScopes, grantedOidcScopes } from '../../src/lib/oidc.ts'

const UPDATED = new Date('2026-01-02T03:04:05Z')
const user = {
  email: 'a@b.com',
  emailVerified: true,
  name: 'Ada L',
  givenName: 'Ada',
  familyName: 'L',
  picture: null,
  updatedAt: UPDATED,
}

Deno.test('grantedOidcScopes keeps only supported scopes in canonical order', () => {
  assertEquals(grantedOidcScopes('email openid profile foo'), [
    'openid',
    'email',
    'profile',
  ])
  assertEquals(grantedOidcScopes(''), [])
  assertEquals(grantedOidcScopes('offline_access'), [])
})

Deno.test('claimsForScopes maps email + profile and omits null fields', () => {
  assertEquals(claimsForScopes(user, ['openid']), {})
  assertEquals(claimsForScopes(user, ['email']), {
    email: 'a@b.com',
    email_verified: true,
  })
  const p = claimsForScopes(user, ['profile'])
  assertEquals(p.name, 'Ada L')
  assertEquals(p.given_name, 'Ada')
  assertEquals(p.family_name, 'L')
  assertEquals('picture' in p, false) // null omitted
  assertEquals(p.updated_at, Math.floor(UPDATED.getTime() / 1000))
})

Deno.test('claimsForScopes defaults email_verified to false when absent', () => {
  assertEquals(
    claimsForScopes({ email: 'x@y.com', updatedAt: UPDATED }, ['email']),
    {
      email: 'x@y.com',
      email_verified: false,
    },
  )
})
