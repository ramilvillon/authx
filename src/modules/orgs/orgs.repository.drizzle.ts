import { and, eq } from 'drizzle-orm'
import type { Database } from '../../db/client.ts'
import { appServices, memberships, organizations } from '../../db/schema.ts'
import type { AppServiceRecord, OrgRepository } from './orgs.repository.ts'

function toService(row: typeof appServices.$inferSelect): AppServiceRecord {
  return {
    ...row,
    type: row.type as 'public' | 'confidential',
    redirectUris: JSON.parse(row.redirectUris) as string[],
    guestsEnabled: row.guestsEnabled,
  }
}

export function createDrizzleOrgRepository(db: Database): OrgRepository {
  return {
    async createOrg(o) {
      await db.insert(organizations).values(o)
      return o
    },
    async findOrgBySlug(slug) {
      const row = await db.query.organizations.findFirst({
        where: eq(organizations.slug, slug),
      })
      return row ?? null
    },
    async findOrgById(id) {
      const row = await db.query.organizations.findFirst({
        where: eq(organizations.id, id),
      })
      return row ?? null
    },
    async listOrgs() {
      return await db.select().from(organizations)
    },
    async createService(s) {
      await db.insert(appServices).values({
        ...s,
        redirectUris: JSON.stringify(s.redirectUris),
        guestsEnabled: s.guestsEnabled ?? false,
      })
      return s
    },
    async findServiceById(id) {
      const row = await db.query.appServices.findFirst({
        where: eq(appServices.id, id),
      })
      return row ? toService(row) : null
    },
    async findServiceByAudience(audience) {
      const row = await db.query.appServices.findFirst({
        where: eq(appServices.audience, audience),
      })
      return row ? toService(row) : null
    },
    async findServiceByClientId(clientId) {
      const row = await db.query.appServices.findFirst({
        where: eq(appServices.clientId, clientId),
      })
      return row ? toService(row) : null
    },
    async listServicesByOrg(orgId) {
      const rows = await db.select().from(appServices).where(
        eq(appServices.orgId, orgId),
      )
      return rows.map(toService)
    },
    async addMember(m) {
      await db.insert(memberships).values(m)
        .onDuplicateKeyUpdate({ set: { userId: m.userId } })
    },
    async removeMember(userId, orgId) {
      await db.delete(memberships).where(
        and(eq(memberships.userId, userId), eq(memberships.orgId, orgId)),
      )
    },
    async removeAllMemberships(userId) {
      const [res] = await db.delete(memberships).where(
        eq(memberships.userId, userId),
      )
      return (res as { affectedRows: number }).affectedRows
    },
    async isMember(userId, orgId) {
      const row = await db.query.memberships.findFirst({
        where: and(
          eq(memberships.userId, userId),
          eq(memberships.orgId, orgId),
        ),
      })
      return !!row
    },
  }
}
