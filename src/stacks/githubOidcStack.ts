import { GithubOidcConfig } from "../config";
import { createGithubOidc } from "../githubOidc";

export function createGithubOidcStack(config: GithubOidcConfig) {
  return createGithubOidc(config);
}
