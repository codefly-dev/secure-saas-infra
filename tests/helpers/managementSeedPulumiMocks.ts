import * as pulumi from "@pulumi/pulumi";

export interface CapturedSeedResource {
  type: string;
  name: string;
  inputs: Record<string, any>;
}

export async function installManagementSeedPulumiMocks() {
  const resources: CapturedSeedResource[] = [];

  await pulumi.runtime.setMocks(
    {
      newResource(
        args: pulumi.runtime.MockResourceArgs,
      ): pulumi.runtime.MockResourceResult {
        resources.push({
          type: args.type,
          name: args.name,
          inputs: args.inputs,
        });
        const id = `${args.name}_id`;
        return {
          id,
          state: {
            ...args.inputs,
            id,
            arn: mockArn(args.type, args.name),
            name: args.inputs.name ?? args.name,
            roots:
              args.type === "aws:organizations/organization:Organization"
                ? [
                    {
                      id: "r-root",
                      arn: "arn:aws:organizations::111111111111:root/o-example/r-root",
                      name: "Root",
                    },
                  ]
                : args.inputs.roots,
          },
        };
      },
      call(args: pulumi.runtime.MockCallArgs): pulumi.runtime.MockCallResult {
        if (args.token.includes("getOrganization")) {
          return {
            id: "o-example",
            arn: "arn:aws:organizations::111111111111:organization/o-example",
            featureSet: "ALL",
            masterAccountArn:
              "arn:aws:organizations::111111111111:account/o-example/111111111111",
            masterAccountEmail: "aws-management@example.com",
            masterAccountId: "111111111111",
            masterAccountName: "management",
            accounts: [],
            nonMasterAccounts: [],
            awsServiceAccessPrincipals: [],
            enabledPolicyTypes: ["SERVICE_CONTROL_POLICY"],
            roots: [
              {
                id: "r-root",
                arn: "arn:aws:organizations::111111111111:root/o-example/r-root",
                name: "Root",
              },
            ],
          };
        }
        return args.inputs;
      },
    },
    "secure-saas-infra-management-seed",
    "unit",
    false,
    "deus",
  );

  return { resources };
}

export async function flushManagementSeedPulumiMocks() {
  for (let index = 0; index < 10; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

export function seedResourcesOfType(
  resources: CapturedSeedResource[],
  type: string,
) {
  return resources.filter((resource) => resource.type === type);
}

function mockArn(type: string, name: string) {
  const service = type.split(":")[1]?.split("/")[0] ?? "mock";
  return `arn:aws:${service}:us-east-1:111111111111:${name}`;
}
