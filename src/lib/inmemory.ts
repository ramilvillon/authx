// Helpers for the in-memory repository doubles, which exist so the unit and
// integration suites run without MySQL.
//
// A double is only useful while it refuses what the database refuses. A `Map`
// has no PRIMARY KEY and no UNIQUE index, so without these a test can prove
// behaviour MySQL would never allow -- which is how the email-change path
// shipped with no uniqueness guard behind a fully green suite. Every double
// that inserts a row checks its table's constraints on the way in.

// Every char column in the schema is utf8mb4_0900_ai_ci, so MySQL matches and
// de-duplicates at UCA *primary* strength: it ignores case AND accents, and
// folds a good deal more besides -- 'ss' = 'ß', 'ae' = 'æ', 'a' = 'ａ',
// 'あ' = 'ア'. Comparing with === (or with toLowerCase, which was the first
// attempt) makes the doubles disagree with the database about which rows can
// exist at all.
//
// Intl.Collator at base sensitivity IS primary strength, so the standard
// library already does this. Measured against MySQL on 55 pairs chosen to
// break it -- ligatures, full-width forms, combining marks, kana, dotless i,
// trailing spaces -- it agreed on every one, where toLowerCase agreed on 4 of
// the first 25. The truth table lives in tests/unit/inmemory-constraints.test.ts.
//
// The locale is pinned deliberately. 'tr' and 'sv' tailor the root order and
// disagree with MySQL (28/30 and 27/30 on that set), an omitted locale follows
// the machine's default, and 'und' does NOT resolve to root -- it also falls
// back to the default locale. So an unpinned collator would make the doubles
// behave one way on a laptop and another in CI. 'en' applies no tailoring on
// top of root, which is the order utf8mb4_0900_ai_ci is built from.
const collator = new Intl.Collator('en', { sensitivity: 'base' })

export function ciEquals(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  return a != null && b != null && collator.compare(a, b) === 0
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
