import type { OrgRepository } from '../orgs/orgs.repository.ts'
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
    if (!s) throw AppError.notFound('service not found')
    return s
  }

  return {
    async createOrg(input: { slug: string; name: string }) {
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
      if (!o) throw AppError.notFound('org not found')
      return o
    },
    async registerService(orgId: string, input: {
      slug: string
      name: string
      audience: string
      type: 'public' | 'confidential'
      redirectUris: string[]
    }) {
      if (!(await orgRepo.findOrgById(orgId))) {
        throw AppError.notFound('org not found')
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
        createdAt: new Date(),
      })
      return { service, clientSecret }
    },
    listServices: (orgId: string) => orgRepo.listServicesByOrg(orgId),
    async addMember(orgId: string, userId: string) {
      if (!(await orgRepo.findOrgById(orgId))) {
        throw AppError.notFound('org not found')
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
      return await rbacRepo.createRole({
        id: crypto.randomUUID(),
        appServiceId: serviceId,
        name,
      })
    },
    async createPermission(serviceId: string, key: string) {
      await requireService(serviceId)
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
