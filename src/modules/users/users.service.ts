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
      const patch: Partial<Pick<UserRecord, 'email' | 'passwordHash'>> = {}
      if (input.email) patch.email = input.email
      if (input.password) {
        patch.passwordHash = await hashPassword(input.password)
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
  }
}
