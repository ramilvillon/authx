// Helpers for the in-memory repository doubles, which exist so the unit and
// integration suites run without MySQL.
//
// A double is only useful while it refuses what the database refuses. A `Map`
// has no PRIMARY KEY and no UNIQUE index, so without these a test can prove
// behaviour MySQL would never allow -- which is how the email-change path
// shipped with no uniqueness guard behind a fully green suite. Every double
// that inserts a row checks its table's constraints on the way in.

// Every char column in the schema is utf8mb4_0900_ai_ci, so MySQL both matches
// and de-duplicates case-insensitively: 'Admin' and 'admin' are one value to a
// UNIQUE index. Comparing with === would make the doubles disagree with the
// database about which rows can exist.
// ponytail: lowercase, not full ai_ci -- the collation also folds accents, but
// no column here has ever held one. This is the single place to change if that
// stops being true.
export function ciEquals(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  return a != null && b != null && a.toLowerCase() === b.toLowerCase()
}

// Mirrors a driver duplicate-key error. The message names the constraint the
// way MySQL does, so a test failure points at the index rather than at the
// double.
export function duplicateKey(
  table: string,
  index: string,
  value: string | null | undefined,
): Error {
  return new Error(`duplicate ${table}.${index} ${value}`)
}
