// TEST_DB=mysql runs the integration suite against the drizzle repositories on a
// real MySQL instead of the in-memory fakes, which are more permissive and once
// hid three bugs behind a green suite. Off by default: the normal run needs no
// database. `make test-db` sets it up (fresh `app_test`, migrated, seeded).
import { createDb, type Database } from '../src/db/client.ts'
import { loadConfig } from '../src/config.ts'

const enabled = Deno.env.get('TEST_DB') === 'mysql'

// Every test truncates every table, so never point this at a database that
// might hold anything worth keeping.
const dbName = Deno.env.get('DB_NAME') ?? ''
if (enabled && !dbName.endsWith('_test')) {
  throw new Error(
    `TEST_DB=mysql wipes the database before every test; refusing DB_NAME="${dbName}" (must end in _test)`,
  )
}

const conn = enabled ? createDb(loadConfig(Deno.env.toObject())) : null
export const testDb: Database | null = conn?.db ?? null

// Tables as seeded, captured once and restored before each test. Deno loads
// helpers.ts afresh for every test file, so "once" has to live in the database
// (`create table if not exists`): a per-file snapshot would capture the rows the
// previous file left behind. It stays valid because `make test-db` recreates
// the database on every run.
let tables: string[] = []

async function snapshot(pool: NonNullable<typeof conn>['pool']) {
  const [rows] = await pool.query(
    `select table_name as t from information_schema.tables
     where table_schema = database() and table_name not like '\\_\\_%'`,
  )
  tables = (rows as { t: string }[]).map((r) => r.t)
  for (const t of tables) {
    await pool.query(
      `create table if not exists \`__snap_${t}\` as select * from \`${t}\``,
    )
  }
}

async function reset(pool: NonNullable<typeof conn>['pool']) {
  const c = await pool.getConnection()
  try {
    await c.query('set foreign_key_checks = 0')
    for (const t of tables) {
      await c.query(`truncate table \`${t}\``)
      await c.query(`insert into \`${t}\` select * from \`__snap_${t}\``)
    }
    await c.query('set foreign_key_checks = 1')
  } finally {
    c.release()
  }
}

if (conn) {
  await snapshot(conn.pool)
  // ponytail: wraps Deno.test globally instead of editing ~110 makeTestApp call
  // sites. Only the two forms the suite uses are supported; anything else throws
  // so a new form fails loudly rather than skipping the reset. The shared pool
  // outlives each test, so the resource/op sanitizers are off in this mode only.
  const register = Deno.test
  const withReset =
    (fn: (t: Deno.TestContext) => unknown | Promise<unknown>) =>
    async (t: Deno.TestContext) => {
      await reset(conn.pool)
      await fn(t)
    }
  const unsanitized = { sanitizeOps: false, sanitizeResources: false }
  Object.assign(Deno, {
    test(a: string | Deno.TestDefinition, b?: unknown) {
      if (typeof a === 'string' && typeof b === 'function') {
        return register({ name: a, fn: withReset(b as never), ...unsanitized })
      }
      if (typeof a === 'object' && b === undefined) {
        return register({ ...a, fn: withReset(a.fn), ...unsanitized })
      }
      throw new Error('mysql-mode: unsupported Deno.test signature')
    },
  })
}
