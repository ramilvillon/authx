import type {
  AppServiceUpdate,
  OrgRepository,
} from '../orgs/orgs.repository.ts'
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
    if (!s) throw AppError.of('service_not_found')
    return s
  }

  return {
    async createOrg(input: { slug: string; name: string }) {
      if (await orgRepo.findOrgBySlug(input.slug)) {
        throw AppError.of('org_slug_taken')
      }
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
      if (!o) throw AppError.of('org_not_found')
      return o
    },
    async registerService(orgId: string, input: {
      slug: string
      name: string
      audience: string
      type: 'public' | 'confidential'
      redirectUris: string[]
      // Optional here (unlike the required zod field, which always supplies a
      // default) so existing direct callers -- like the drizzle-only e2e test
      // that predates this field -- keep compiling.
      guestsEnabled?: boolean
    }) {
      if (!(await orgRepo.findOrgById(orgId))) {
        throw AppError.of('org_not_found')
      }
      // The audience is what an access token's `aud` claim carries, so two
      // services sharing one would be indistinguishable to requireAuth. The
      // client id is generated here rather than supplied, so it needs no check.
      if (await orgRepo.findServiceByAudience(input.audience)) {
        throw AppError.of('service_audience_taken')
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
        guestsEnabled: input.guestsEnabled ?? false,
        createdAt: new Date(),
      })
      return { service, clientSecret }
    },
    listServices: (orgId: string) => orgRepo.listServicesByOrg(orgId),
    async updateService(id: string, patch: AppServiceUpdate) {
      const service = await orgRepo.updateService(id, patch)
      if (!service) throw AppError.of('service_not_found')
      return service
    },
    async addMember(orgId: string, userId: string) {
      if (!(await orgRepo.findOrgById(orgId))) {
        throw AppError.of('org_not_found')
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
      if (await rbacRepo.findRoleByName(serviceId, name)) {
        throw AppError.of('role_name_taken')
      }
      return await rbacRepo.createRole({
        id: crypto.randomUUID(),
        appServiceId: serviceId,
        name,
      })
    },
    async createPermission(serviceId: string, key: string) {
      await requireService(serviceId)
      if (await rbacRepo.findPermissionByKey(serviceId, key)) {
        throw AppError.of('permission_key_taken')
      }
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
    assignRoleToClient: (clientAppServiceId: string, roleId: string) =>
      rbacRepo.assignRoleToClient(clientAppServiceId, roleId),
  }
}
