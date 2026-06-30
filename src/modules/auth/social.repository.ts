export type SocialAccountRepository = {
  findByProviderAccount(
    provider: string,
    providerAccountId: string,
  ): Promise<{ userId: string } | null>
  link(account: {
    id: string
    userId: string
    provider: string
    providerAccountId: string
  }): Promise<void>
}
