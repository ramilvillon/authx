import { AppError } from './errors.ts'

// bcrypt hashes at most 72 bytes and silently ignores the rest, so two long
// passwords sharing a 72-byte prefix authenticate each other. Refusing the
// input is a one-line fix; migrating to a scheme without the limit would mean
// a new dependency and rehashing every stored password.
// ponytail: switch to Argon2id if a real user ever wants longer passphrases.
const MAX_BYTES = 72

// NIST SP 800-63B-4 sets 8 as the floor for a memorized secret and recommends
// more. Operators can raise it; they cannot lower it below the floor.
export const MIN_LENGTH = 8

// Read once, on first use rather than at import, so a tool that imports this
// module for its types does not pay for the file.
let common: Set<string> | null = null

function commonPasswords(): Set<string> {
  if (!common) {
    const text = Deno.readTextFileSync(
      new URL('./common-passwords.txt', import.meta.url),
    )
    common = new Set(
      text.split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#')),
    )
  }
  return common
}

// Every path where a person CHOOSES a password calls this: registration, a
// self-service change, and a reset. Generated secrets (guest passwords, the
// timing-attack dummy hash) deliberately do not -- they are random, and a
// blocklist hit on one would be a false positive that breaks sign-up.
export function assertAcceptablePassword(
  password: string,
  minLength: number = MIN_LENGTH,
): void {
  // Byte length, not `.length`: bcrypt counts bytes, and a single emoji is
  // four of them.
  if (new TextEncoder().encode(password).length > MAX_BYTES) {
    throw AppError.of('password_too_long')
  }
  const floor = Math.max(minLength, MIN_LENGTH)
  if (password.length < floor) {
    throw AppError.of(
      'weak_password',
      `password must be at least ${floor} characters`,
    )
  }
  // The list is stored lowercased: capitalising the first letter is the most
  // common way around a blocklist, and it makes the password no harder to
  // guess.
  if (commonPasswords().has(password.toLowerCase())) {
    throw AppError.of('weak_password')
  }
}
