import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { GithubOidcConfig, GithubOidcRepositoryConfig, baseTags, named } from "./config";

export function createGithubOidc(config: GithubOidcConfig) {
  if (!config.enabled || config.repositories.length === 0) {
    return { roles: {} };
  }

  // No thumbprintList: AWS now manages the certificate trust library for
  // token.actions.githubusercontent.com. See:
  // https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
  const provider = new aws.iam.OpenIdConnectProvider(named("github-actions-oidc"), {
    url: "https://token.actions.githubusercontent.com",
    clientIdLists: ["sts.amazonaws.com"],
    tags: tag("github-actions-oidc"),
  });

  const roles: Record<string, aws.iam.Role> = {};
  for (const repository of config.repositories) {
    const roleKey = repository.name ?? `${repository.owner}/${repository.repo}`;
    const resourceName = repository.name
      ? `github-${slug(repository.name)}`
      : `github-${slug(repository.owner)}-${slug(repository.repo)}`;
    const role = new aws.iam.Role(named(resourceName), {
      assumeRolePolicy: pulumi.all([provider.arn]).apply(([providerArn]) =>
        JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: {
                Federated: providerArn,
              },
              Action: "sts:AssumeRoleWithWebIdentity",
              Condition: {
                StringEquals: {
                  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                },
                StringLike: {
                  "token.actions.githubusercontent.com:sub": allowedSubjects(repository),
                },
              },
            },
          ],
        }),
      ),
      description: repository.description ?? `GitHub Actions OIDC role for ${repository.owner}/${repository.repo}.`,
      maxSessionDuration: repository.maxSessionDurationSeconds ?? 3600,
      tags: tag(resourceName, {
        GithubRole: roleKey,
        GithubOwner: repository.owner,
        GithubRepository: repository.repo,
      }),
    });

    roles[roleKey] = role;

    repository.managedPolicyArns.forEach((policyArn, index) => {
      new aws.iam.RolePolicyAttachment(named(`${resourceName}-policy-${index + 1}`), {
        role: role.name,
        policyArn,
      });
    });

    if (repository.inlinePolicy) {
      new aws.iam.RolePolicy(named(`${resourceName}-inline`), {
        role: role.id,
        policy: JSON.stringify(repository.inlinePolicy),
      });
    }
  }

  return { roles };
}

function allowedSubjects(repository: GithubOidcRepositoryConfig) {
  const refs = repository.allowedRefs.map((ref) => `repo:${repository.owner}/${repository.repo}:ref:${ref}`);
  const environments = repository.allowedEnvironments.map(
    (environment) => `repo:${repository.owner}/${repository.repo}:environment:${environment}`,
  );
  return [...refs, ...environments];
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
