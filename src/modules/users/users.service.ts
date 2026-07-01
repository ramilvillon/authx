import type { UserRecord, UserRepository } from './users.repository.ts'
import type {
  PublicUser,
  RegisterInput,
  UpdateUserInput,
} from './users.schema.ts'
import { hashPassword } from '../../lib/password.ts'
import { AppError } from '../../lib/errors.ts'

export type UserService = ReturnType<typeof createUserService>

function toPublic(u: UserRecord): PublicUser {
  return { id: u.id, email: u.email, createdAt: u.createdAt }
}

export function createUserService(deps: { repo: UserRepository }) {
  const { repo } = deps
  return {
    async register(input: RegisterInput): Promise<PublicUser> {
      if (await repo.findByEmail(input.email)) {
        throw AppError.conflict('email already registered')
      }
      const now = new Date()
      const user = await repo.create({
        id: crypto.randomUUID(),
        email: input.email,
        passwordHash: await hashPassword(input.password),
        createdAt: now,
        updatedAt: now,
      })
      await repo.assignRole(user.id, 'user')
      return toPublic(user)
    },
    async getById(id: string): Promise<PublicUser> {
      const u = await repo.findById(id)
      if (!u) throw AppError.notFound('user not found')
      return toPublic(u)
    },
    async update(id: string, input: UpdateUserInput): Promise<PublicUser> {
      const current = await repo.findById(id)
      if (!current) throw AppError.notFound('user not found')
      const patch: Partial<
        Pick<
          UserRecord,
          | 'email'
          | 'passwordHash'
          | 'emailVerified'
          | 'name'
          | 'givenName'
          | 'familyName'
          | 'picture'
        >
      > = {}
      if (input.email) patch.email = input.email
      if (input.password) {
        patch.passwordHash = await hashPassword(input.password)
      }
      if (input.name !== undefined) patch.name = input.name
      if (input.given_name !== undefined) patch.givenName = input.given_name
      if (input.family_name !== undefined) patch.familyName = input.family_name
      if (input.picture !== undefined) patch.picture = input.picture
      // A new email address is unverified until it is re-verified.
      if (input.email && input.email !== current.email) {
        patch.emailVerified = false
      }
      const u = await repo.update(id, patch)
      if (!u) throw AppError.notFound('user not found')
      return toPublic(u)
    },
    async remove(id: string): Promise<void> {
      if (!(await repo.delete(id))) throw AppError.notFound('user not found')
    },
    async list(): Promise<PublicUser[]> {
      return (await repo.list()).map(toPublic)
    },
    getUserRecord(id: string): Promise<UserRecord | null> {
      return repo.findById(id)
    },
  }
}
