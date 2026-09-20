import { assertEquals } from '@std/assert'
import { makeTestApp, seedDefaultService } from '../helpers.ts'

Deno.test('POST /users registers a user', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'a@b.com', password: 'pw123456' }),
  })
  assertEquals(res.status, 201)
  const body = await res.json()
  assertEquals(body.email, 'a@b.com')
})

Deno.test('POST /users validation error -> 400', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'nope', password: 'x' }),
  })
  assertEquals(res.status, 400)
})

// The column is varchar(255) and MySQL runs in STRICT_TRANS_TABLES, so an
// over-length address is error 1406 at the driver -- a 500 -- while a Map
// accepts it. Every admin schema already caps to its column width; email was
// the one that did not.
Deno.test('POST /users rejects an address longer than the column -> 400, not a driver error', async () => {
  const { app } = makeTestApp()
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email: `${'x'.repeat(250)}@b.com`, // 256 chars
      password: 'pw123456',
    }),
  })
  assertEquals(res.status, 400)
})

// users.email is UNIQUE under utf8mb4_0900_ai_ci, which is case-insensitive:
// MySQL considers these the same address and refuses the second row. The
// in-memory double compared with === and let it through, so the two
// implementations disagreed about whether this account could exist at all.
Deno.test('POST /users treats a case-differing address as taken', async () => {
  const { app } = makeTestApp()
  const first = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'casey@b.com', password: 'pw123456' }),
  })
  assertEquals(first.status, 201)
  const res = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'CASEY@b.com', password: 'pw123456' }),
  })
  assertEquals(res.status, 409)
})

// The lookup is collation-insensitive in production; the double has to be too,
// or a test can encode a case-sensitive login that real MySQL does not have.
Deno.test('the password grant accepts a case-differing address', async () => {
  const { app, orgRepo } = makeTestApp()
  const reg = await app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'mixed@b.com', password: 'pw123456' }),
  })
  const audience = await seedDefaultService(orgRepo, (await reg.json()).id)
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'password',
      username: 'MIXED@B.com',
      password: 'pw123456',
      audience,
    }),
  })
  assertEquals(res.status, 200)
})

// utf8mb4_0900_ai_ci compares at primary strength, so it folds accents as well
// as case and 'cafe@b.com' and 'café@b.com' would be one address to the UNIQUE
// index. That never arises, because zod's .email() is ASCII-only and rejects
// the address before any repository sees it. Pinned here so the next person
// checking whether the accent case is handled finds the answer -- it is
// excluded at the trust boundary, not handled downstream. Loosening .email()
// to allow an internationalised address would make the folding reachable.
Deno.test('POST /users rejects a non-ASCII address at the schema', async () => {
  const { app } = makeTestApp()
  for (const email of ['café@b.com', 'ısmail@b.com', 'user@bü.com']) {
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: 'pw123456' }),
    })
    assertEquals(res.status, 400, `${email} should be refused as invalid`)
  }
})
