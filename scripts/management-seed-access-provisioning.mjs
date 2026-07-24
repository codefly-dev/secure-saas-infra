import { canonicalJson, sha256 } from "./management-seed-scope.mjs";

export const ACCESS_STACK_NAME = "deus-management-seed-access";
export const EXECUTE_CONFIRMATION =
  "INSTALL_EXACTLY_TWO_BOUNDED_IAM_ROLE_POLICIES";
export const RETIRE_CONFIRMATION = "RETIRE_EXACT_MANAGEMENT_SEED_PROVISIONER";
export const PROVISIONER_RETIREMENT_OPERATIONS = Object.freeze([
  "iam:PutRolePermissionsBoundary",
  "iam:DeleteRolePolicy",
  "iam:TagRole",
]);

const EXPECTED_CHANGES = new Map([
  ["ApplyRolePolicy", "AWS::IAM::RolePolicy"],
  ["PreviewRolePolicy", "AWS::IAM::RolePolicy"],
]);

const FOUNDATION_OBSERVATION_COMMANDS = new Set([
  "iam:get-policy",
  "iam:get-policy-version",
  "iam:get-role",
  "iam:get-role-policy",
  "iam:get-saml-provider",
  "iam:list-attached-role-policies",
  "iam:list-policy-versions",
  "iam:list-role-policies",
  "sts:get-caller-identity",
]);

export function assertFoundationObservationAwsCommand(args) {
  const command =
    Array.isArray(args) && args.length >= 2 ? `${args[0]}:${args[1]}` : "";
  if (!FOUNDATION_OBSERVATION_COMMANDS.has(command)) {
    throw new Error(
      `foundation observation forbids AWS command '${command || "malformed"}'`,
    );
  }
}

export function expectedAccessChangeSetName(bundleDigest) {
  if (!/^[a-f0-9]{64}$/.test(bundleDigest)) {
    throw new Error("access bundle digest is invalid");
  }
  return `${ACCESS_STACK_NAME}-${bundleDigest.slice(0, 12)}`;
}

export function prepareAccessChangeSet(bundle, templateSource, aws) {
  const validation = aws.json([
    "cloudformation",
    "validate-template",
    "--region",
    bundle.provisioning.region,
    "--template-body",
    templateSource,
  ]);
  if (canonicalJson(validation.Capabilities ?? []) !== canonicalJson([])) {
    throw new Error(
      "CloudFormation validation reported capabilities for the exact RolePolicy-only template",
    );
  }
  const changeSetName = expectedAccessChangeSetName(bundle.bundleDigest);
  const created = aws.json([
    "cloudformation",
    "create-change-set",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
    "--change-set-name",
    changeSetName,
    "--change-set-type",
    "CREATE",
    "--template-body",
    templateSource,
    "--description",
    accessChangeSetDescription(bundle),
    "--client-token",
    `prepare-${bundle.bundleDigest.slice(0, 32)}`,
  ]);
  if (typeof created.Id !== "string") {
    throw new Error("CloudFormation did not return a change-set ID");
  }
  aws.run([
    "cloudformation",
    "wait",
    "change-set-create-complete",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
    "--change-set-name",
    created.Id,
  ]);
  return reverifyAccessChangeSet(bundle, created.Id, aws);
}

export function reverifyAccessChangeSet(
  bundle,
  changeSetId,
  aws,
  { executionStatus = "AVAILABLE" } = {},
) {
  const description = aws.json([
    "cloudformation",
    "describe-change-set",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
    "--change-set-name",
    changeSetId,
  ]);
  assertExactAccessChangeSet(bundle, description, { executionStatus });
  const template = aws.json([
    "cloudformation",
    "get-template",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
    "--change-set-name",
    changeSetId,
    "--template-stage",
    "Original",
  ]).TemplateBody;
  const body =
    typeof template === "string" ? parseTemplate(template) : template;
  if (canonicalJson(body) !== canonicalJson(bundle.cloudFormationTemplate)) {
    throw new Error("stored CloudFormation template changed");
  }
  return description;
}

export function executeAccessChangeSet(bundle, changeSetId, aws) {
  aws.run([
    "cloudformation",
    "execute-change-set",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
    "--change-set-name",
    changeSetId,
    "--client-request-token",
    `execute-${bundle.bundleDigest.slice(0, 32)}`,
  ]);
  aws.run([
    "cloudformation",
    "wait",
    "stack-create-complete",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
  ]);
  return observeCompletedAccessStack(bundle, aws);
}

export function observeCompletedAccessStack(bundle, aws) {
  const stacks = aws.json([
    "cloudformation",
    "describe-stacks",
    "--region",
    bundle.provisioning.region,
    "--stack-name",
    ACCESS_STACK_NAME,
  ]).Stacks;
  if (!Array.isArray(stacks) || stacks.length !== 1) {
    throw new Error("CloudFormation did not return one exact access stack");
  }
  return stacks[0];
}

export function assertExactAccessChangeSet(
  bundle,
  description,
  { executionStatus = "AVAILABLE" } = {},
) {
  if (!["AVAILABLE", "EXECUTE_COMPLETE"].includes(executionStatus)) {
    throw new Error("expected change-set execution status is invalid");
  }
  if (description?.StackName !== ACCESS_STACK_NAME) {
    throw new Error("change set uses the wrong stack name");
  }
  const expectedName = expectedAccessChangeSetName(bundle.bundleDigest);
  if (description.ChangeSetName !== expectedName) {
    throw new Error("change set uses the wrong deterministic name");
  }
  if (
    description.Status !== "CREATE_COMPLETE" ||
    description.ExecutionStatus !== executionStatus
  ) {
    throw new Error(
      `change set is not complete with execution status ${executionStatus}`,
    );
  }
  if (description.ChangeSetType !== "CREATE") {
    throw new Error("access change set must create a fresh stack");
  }
  if (canonicalJson(description.Capabilities ?? []) !== canonicalJson([])) {
    throw new Error("change set capabilities are not exact");
  }
  if (
    (description.Parameters?.length ?? 0) !== 0 ||
    (description.Tags?.length ?? 0) !== 0 ||
    description.IncludeNestedStacks === true
  ) {
    throw new Error("change set has parameters, tags, or nested stacks");
  }
  const expectedDescription = accessChangeSetDescription(bundle);
  if (description.Description !== expectedDescription) {
    throw new Error(
      "change set description does not bind the artifact digests",
    );
  }
  const changeSetIdPattern = new RegExp(
    `^arn:${escape(bundle.awsPartition)}:cloudformation:${escape(bundle.provisioning.region)}:${escape(bundle.managementAccountId)}:changeSet/${escape(expectedName)}/[A-Za-z0-9-]+$`,
  );
  const stackIdPattern = new RegExp(
    `^arn:${escape(bundle.awsPartition)}:cloudformation:${escape(bundle.provisioning.region)}:${escape(bundle.managementAccountId)}:stack/${escape(ACCESS_STACK_NAME)}/[A-Za-z0-9-]+$`,
  );
  if (!changeSetIdPattern.test(description.ChangeSetId ?? "")) {
    throw new Error("change set ID is outside the exact account and region");
  }
  if (!stackIdPattern.test(description.StackId ?? "")) {
    throw new Error(
      "change set stack ID is outside the exact account and region",
    );
  }
  if (!Array.isArray(description.Changes)) {
    throw new Error("change set has no resource inventory");
  }
  const changes = description.Changes.map((entry) => {
    if (entry?.Type !== "Resource" || !entry.ResourceChange) {
      throw new Error("change set contains a non-resource change");
    }
    const change = entry.ResourceChange;
    if (
      change.Action !== "Add" ||
      !EXPECTED_CHANGES.has(change.LogicalResourceId) ||
      EXPECTED_CHANGES.get(change.LogicalResourceId) !== change.ResourceType ||
      ![undefined, null, "False", "Never"].includes(change.Replacement)
    ) {
      throw new Error("change set contains an unexpected IAM resource change");
    }
    return {
      action: change.Action,
      logicalResourceId: change.LogicalResourceId,
      resourceType: change.ResourceType,
    };
  });
  changes.sort((left, right) =>
    left.logicalResourceId.localeCompare(right.logicalResourceId),
  );
  if (
    changes.length !== EXPECTED_CHANGES.size ||
    new Set(changes.map((entry) => entry.logicalResourceId)).size !==
      EXPECTED_CHANGES.size
  ) {
    throw new Error("change set must contain exactly two unique role policies");
  }
  return changes;
}

export function createPreparedAccessReceipt({
  bundle,
  candidateDigest,
  callerArn,
  description,
  generatedAt = new Date().toISOString(),
}) {
  const changes = assertExactAccessChangeSet(bundle, description);
  const subject = {
    apiVersion:
      "security.deus.dev/management-seed-access-change-set-receipt/v1",
    kind: "ManagementSeedAccessChangeSetReceipt",
    stage: "prepared",
    generatedAt,
    candidateDigest,
    bundleDigest: bundle.bundleDigest,
    cloudFormationTemplateFileSha256: bundle.cloudFormationTemplateFileSha256,
    managementAccountId: bundle.managementAccountId,
    awsPartition: bundle.awsPartition,
    region: bundle.provisioning.region,
    stackName: ACCESS_STACK_NAME,
    callerArn,
    cloudControlPlaneMutationPerformed: true,
    iamMutationPerformed: false,
    changeSet: {
      id: description.ChangeSetId,
      name: description.ChangeSetName,
      stackId: description.StackId,
      status: description.Status,
      executionStatus: description.ExecutionStatus,
      changes,
      changesDigest: sha256(canonicalJson(changes)),
    },
    provisionerRetirementRequired: true,
  };
  return { ...subject, receiptDigest: sha256(canonicalJson(subject)) };
}

export function createFoundationObservationReceipt({
  bundle,
  candidateDigest,
  callerArn,
  attestation,
  generatedAt = new Date().toISOString(),
}) {
  const { attestationDigest, ...attestationSubject } = attestation ?? {};
  if (
    attestation?.apiVersion !==
      "security.deus.dev/management-seed-access-foundation-attestation/v1" ||
    attestation.pass !== true ||
    attestation.managementAccountId !== bundle.managementAccountId ||
    attestation.awsPartition !== bundle.awsPartition ||
    attestation.managementAccessRegion !== bundle.provisioning.region ||
    attestation.bundleDigest !== bundle.bundleDigest ||
    attestationDigest !== sha256(canonicalJson(attestationSubject))
  ) {
    throw new Error("foundation observation attestation is invalid");
  }
  const expectedCallerPrefix = `arn:${bundle.awsPartition}:sts::${bundle.managementAccountId}:assumed-role/ManagementSeedProvisioner/`;
  if (
    typeof callerArn !== "string" ||
    !callerArn.startsWith(expectedCallerPrefix) ||
    callerArn.slice(expectedCallerPrefix.length).length === 0 ||
    callerArn.slice(expectedCallerPrefix.length).includes("/")
  ) {
    throw new Error("foundation observation caller is invalid");
  }
  const subject = {
    apiVersion:
      "security.deus.dev/management-seed-access-foundation-observation-receipt/v1",
    kind: "ManagementSeedAccessFoundationObservationReceipt",
    generatedAt,
    candidateDigest,
    bundleDigest: bundle.bundleDigest,
    managementAccountId: bundle.managementAccountId,
    awsPartition: bundle.awsPartition,
    region: bundle.provisioning.region,
    callerArn,
    foundationAttestationDigest: attestationDigest,
    cloudControlPlaneMutationPerformed: false,
    iamMutationPerformed: false,
  };
  return { ...subject, receiptDigest: sha256(canonicalJson(subject)) };
}

export function createExecutedAccessReceipt({
  prepared,
  candidateDigest,
  callerArn,
  stack,
  attestation,
  recoveredAfterPriorExecution = false,
  generatedAt = new Date().toISOString(),
}) {
  assertPreparedAccessReceipt(prepared);
  if (
    prepared.candidateDigest !== candidateDigest ||
    prepared.callerArn !== callerArn ||
    typeof recoveredAfterPriorExecution !== "boolean"
  ) {
    throw new Error(
      "prepared receipt does not bind this candidate, caller, and recovery state",
    );
  }
  if (
    stack?.StackId !== prepared.changeSet.stackId ||
    stack?.StackName !== prepared.stackName ||
    stack?.StackStatus !== "CREATE_COMPLETE"
  ) {
    throw new Error("access stack did not reach exact CREATE_COMPLETE state");
  }
  if (
    attestation?.pass !== true ||
    attestation.bundleDigest !== prepared.bundleDigest
  ) {
    throw new Error("post-create access attestation did not pass");
  }
  const { receiptDigest: preparedReceiptDigest } = prepared;
  const subject = {
    ...prepared,
    stage: "executed",
    generatedAt,
    cloudControlPlaneMutationPerformed: !recoveredAfterPriorExecution,
    iamMutationPerformed: !recoveredAfterPriorExecution,
    preparedReceiptDigest,
    execution: {
      stackStatus: stack.StackStatus,
      attestationDigest: attestation.attestationDigest,
      provisionerAssignmentRetired: false,
      recoveredAfterPriorExecution,
    },
  };
  delete subject.receiptDigest;
  return { ...subject, receiptDigest: sha256(canonicalJson(subject)) };
}

export function performNextProvisionerRetirementOperation(
  bundle,
  progress,
  aws,
) {
  const retirement = bundle.provisioning.retirement;
  const roleName = bundle.provisioning.principalArn.split("/").at(-1);
  const prefixes = {
    active: [],
    bounded: ["iam:PutRolePermissionsBoundary"],
    stripped: ["iam:PutRolePermissionsBoundary", "iam:DeleteRolePolicy"],
    retired: PROVISIONER_RETIREMENT_OPERATIONS,
  };
  if (
    progress?.roleArn !== bundle.provisioning.principalArn ||
    progress.boundaryArn !== retirement.permissionsBoundaryArn ||
    progress.progressDigest !==
      sha256(canonicalJson(without(progress, "progressDigest"))) ||
    !Object.hasOwn(prefixes, progress.state) ||
    canonicalJson(progress.completedOperations) !==
      canonicalJson(prefixes[progress.state])
  ) {
    throw new Error(
      "provisioner retirement progress is not exact or bundle-bound",
    );
  }
  if (progress.state === "retired") return null;
  if (progress.state === "active") {
    aws.run([
      "iam",
      "put-role-permissions-boundary",
      "--role-name",
      roleName,
      "--permissions-boundary",
      retirement.permissionsBoundaryArn,
    ]);
    return {
      operation: "iam:PutRolePermissionsBoundary",
      expectedState: "bounded",
    };
  }
  if (progress.state === "bounded") {
    aws.run([
      "iam",
      "delete-role-policy",
      "--role-name",
      roleName,
      "--policy-name",
      bundle.provisioning.active.inlinePolicyName,
    ]);
    return { operation: "iam:DeleteRolePolicy", expectedState: "stripped" };
  }
  aws.run([
    "iam",
    "tag-role",
    "--role-name",
    roleName,
    "--tags",
    ...retirement.requiredRoleTags.map(
      (tag) => `Key=${tag.Key},Value=${tag.Value}`,
    ),
  ]);
  return { operation: "iam:TagRole", expectedState: "retired" };
}

export function createProvisionerRetirementReceipt({
  bundle,
  candidateDigest,
  callerArn,
  executedAccessReceipt,
  attestation,
  startingState,
  performedOperations,
  generatedAt = new Date().toISOString(),
}) {
  if (
    executedAccessReceipt?.stage !== "executed" ||
    executedAccessReceipt.receiptDigest !==
      sha256(canonicalJson(without(executedAccessReceipt, "receiptDigest"))) ||
    executedAccessReceipt.bundleDigest !== bundle.bundleDigest ||
    executedAccessReceipt.candidateDigest !== candidateDigest ||
    executedAccessReceipt.execution?.provisionerAssignmentRetired !== false
  ) {
    throw new Error("executed access receipt does not authorize retirement");
  }
  const expectedPerformedOperations = {
    active: PROVISIONER_RETIREMENT_OPERATIONS,
    bounded: ["iam:DeleteRolePolicy", "iam:TagRole"],
    stripped: ["iam:TagRole"],
    retired: [],
  };
  if (
    !Object.hasOwn(expectedPerformedOperations, startingState) ||
    canonicalJson(performedOperations) !==
      canonicalJson(expectedPerformedOperations[startingState]) ||
    attestation?.pass !== true ||
    attestation.bundleDigest !== bundle.bundleDigest ||
    attestation.observations?.provisionerRetirement?.observed !== true ||
    attestation.observations.provisionerRetirement.state !== "retired"
  ) {
    throw new Error("provisioner retirement postcondition is invalid");
  }
  const subject = {
    apiVersion:
      "security.deus.dev/management-seed-provisioner-retirement-receipt/v1",
    kind: "ManagementSeedProvisionerRetirementReceipt",
    generatedAt,
    candidateDigest,
    bundleDigest: bundle.bundleDigest,
    executedAccessReceiptDigest: executedAccessReceipt.receiptDigest,
    managementAccountId: bundle.managementAccountId,
    awsPartition: bundle.awsPartition,
    region: bundle.provisioning.region,
    callerArn,
    provisionerRoleArn: bundle.provisioning.principalArn,
    retirementAuthorityRoleArn: bundle.provisioning.retirement.principalArn,
    retirementBoundaryArn:
      bundle.provisioning.retirement.permissionsBoundaryArn,
    startingState,
    finalState: "retired",
    orderedOperations: PROVISIONER_RETIREMENT_OPERATIONS,
    performedOperations,
    accessMutationPerformed: performedOperations.length > 0,
    upstreamIdpAssignmentRetired: false,
    attestationDigest: attestation.attestationDigest,
  };
  return { ...subject, receiptDigest: sha256(canonicalJson(subject)) };
}

export function assertPreparedAccessReceipt(receipt) {
  if (
    receipt?.stage !== "prepared" ||
    receipt.iamMutationPerformed !== false ||
    receipt.receiptDigest !==
      sha256(canonicalJson(without(receipt, "receiptDigest")))
  ) {
    throw new Error("prepared access receipt is invalid");
  }
}

export function accessChangeSetDescription(bundle) {
  return `bundle=${bundle.bundleDigest};template=${bundle.cloudFormationTemplateFileSha256}`;
}

function without(value, key) {
  const clone = { ...value };
  delete clone[key];
  return clone;
}

function escape(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseTemplate(value) {
  try {
    const parsed = JSON.parse(value);
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new Error("not an object");
    }
    return parsed;
  } catch (error) {
    throw new Error(
      `stored CloudFormation template is invalid: ${error.message}`,
    );
  }
}
