export const GITHUB_REPOSITORY_URL = "https://github.com/zrk222/code-factory";

export function starPromptKey(): string {
  return "factoryline.githubStarPromptedVersion";
}

export function shouldOfferGitHubStar(promptedForVersion: unknown, installedVersion: string): boolean {
  return typeof promptedForVersion !== "string" || promptedForVersion !== installedVersion;
}
