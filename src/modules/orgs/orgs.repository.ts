export type OrgRecord = {
  id: string
  slug: string
  name: string
  createdAt: Date
}

export type AppServiceRecord = {
  id: string
  orgId: string
  clientId: string
  clientSecretHash: string | null
  name: string
  slug: string
  audience: string
  type: 'public' | 'confidential'
  redirectUris: string[]
  // Optional so existing literals in tests and seed.ts keep compiling.
  // Always read as `=== true` so an absent value fails closed.
  guestsEnabled?: boolean
  createdAt: Date
}

export type MembershipRecord = {
  id: string
  userId: string
  orgId: string
  createdAt: Date
}

export type OrgRepository = {
  createOrg(o: OrgRecord): Promise<OrgRecord>
  findOrgById(id: string): Promise<OrgRecord | null>
  // organizations.slug is UNIQUE; callers check before inserting so a duplicate
  // is reported as a conflict rather than a driver error.
  findOrgBySlug(slug: string): Promise<OrgRecord | null>
  listOrgs(): Promise<OrgRecord[]>
  createService(s: AppServiceRecord): Promise<AppServiceRecord>
  findServiceById(id: string): Promise<AppServiceRecord | null>
  findServiceByAudience(audience: string): Promise<AppServiceRecord | null>
  findServiceByClientId(clientId: string): Promise<AppServiceRecord | null>
  listServicesByOrg(orgId: string): Promise<AppServiceRecord[]>
  addMember(m: MembershipRecord): Promise<void>
  removeMember(userId: string, orgId: string): Promise<void>
  // memberships has no foreign key to users, so a deleted account's org
  // memberships survive and would be inherited by a row reusing the id.
  removeAllMemberships(userId: string): Promise<number>
  isMember(userId: string, orgId: string): Promise<boolean>
}

// In-memory test double. Mirror behavior in orgs.repository.drizzle.ts.
export function createInMemoryOrgRepository(): OrgRepository {
  const orgs = new Map<string, OrgRecord>()
  const services = new Map<string, AppServiceRecord>()
  const members = new Set<string>() // `${userId}:${orgId}`

  return {
    createOrg(o) {
      orgs.set(o.id, { ...o })
      return Promise.resolve({ ...o })
    },
    findOrgById(id) {
      return Promise.resolve(orgs.has(id) ? { ...orgs.get(id)! } : null)
    },
    findOrgBySlug(slug) {
      for (const o of orgs.values()) {
        if (o.slug === slug) return Promise.resolve({ ...o })
      }
      return Promise.resolve(null)
    },
    listOrgs() {
      return Promise.resolve([...orgs.values()].map((o) => ({ ...o })))
    },
    createService(s) {
      services.set(s.id, { ...s })
      return Promise.resolve({ ...s })
    },
    findServiceById(id) {
      return Promise.resolve(services.has(id) ? { ...services.get(id)! } : null)
    },
    findServiceByAudience(audience) {
      for (const s of services.values()) {
        if (s.audience === audience) return Promise.resolve({ ...s })
      }
      return Promise.resolve(null)
    },
    findServiceByClientId(clientId) {
      for (const s of services.values()) {
        if (s.clientId === clientId) return Promise.resolve({ ...s })
      }
      return Promise.resolve(null)
    },
    listServicesByOrg(orgId) {
      return Promise.resolve(
        [...services.values()].filter((s) => s.orgId === orgId).map((s) => ({
          ...s,
        })),
      )
    },
    addMember(m) {
      members.add(`${m.userId}:${m.orgId}`)
      return Promise.resolve()
    },
    removeMember(userId, orgId) {
      members.delete(`${userId}:${orgId}`)
      return Promise.resolve()
    },
    removeAllMemberships(userId) {
      let n = 0
      for (const key of [...members.keys()]) {
        if (key.startsWith(`${userId}:`)) {
          members.delete(key)
          n++
        }
      }
      return Promise.resolve(n)
    },
    isMember(userId, orgId) {
      return Promise.resolve(members.has(`${userId}:${orgId}`))
    },
  }
}
