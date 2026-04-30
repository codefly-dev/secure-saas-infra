import { GithubGovernanceConfig } from "../config";
import { createGithubGovernance } from "../githubGovernance";

export function createGithubGovernanceStack(config: GithubGovernanceConfig) {
  return createGithubGovernance(config);
}
