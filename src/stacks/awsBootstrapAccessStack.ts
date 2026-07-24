import { createAwsBootstrapAccountAccess } from "../awsBootstrapAccess";

export function createAwsBootstrapAccessStack(
  plan: unknown,
  accountName: string,
) {
  return createAwsBootstrapAccountAccess(plan, accountName);
}
