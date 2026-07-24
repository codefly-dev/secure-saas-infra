import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  awsDatabaseInfrastructureHandoffDigest,
  parseAwsDatabaseInfrastructureHandoff,
} from "../src/core";

function fixture(): any {
  return JSON.parse(
    readFileSync(
      "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
      "utf8",
    ),
  );
}

test("checked AWS database infrastructure handoff is pending, content-addressed, and controller-only", () => {
  const handoff = parseAwsDatabaseInfrastructureHandoff(fixture());
  assert.equal(handoff.authorizedConsumer, "infrastructure-controller");
  assert.equal(handoff.applicationMutationAllowed, false);
  assert.equal(
    handoff.deploymentAuthorization.state,
    "pending-identity-binding",
  );
  assert.equal(handoff.accessClasses.bootstrap.podIdentityAssociationId, null);
  assert.match(handoff.handoffSpecDigest, /^[a-f0-9]{64}$/);
  assert.equal(
    awsDatabaseInfrastructureHandoffDigest(handoff),
    handoff.handoffSpecDigest,
  );
});

test("AWS database handoff rejects manifest, association, envelope, and credential substitutions", () => {
  const manifestMutation = fixture();
  manifestMutation.accessClasses.runtime.manifests.namespace.metadata.name =
    "wrong-namespace";
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(manifestMutation),
    /NAMESPACE_SUBSTITUTION/,
  );

  const coherentManagedNameMutation = fixture();
  for (const resource of [
    "admissionPolicy",
    "applicationNetworkPolicy",
    "nodeClass",
    "nodePool",
  ]) {
    coherentManagedNameMutation.accessClasses.runtime.manifests[
      resource
    ].metadata.name = "attacker-runtime-access";
  }
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(coherentManagedNameMutation),
    /NODE_PLACEMENT_SUBSTITUTION/,
  );

  const schedulingMutation = fixture();
  schedulingMutation.accessClasses.runtime.manifests.requiredPodScheduling.tolerations[0].value =
    "substituted-scheduling-value";
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(schedulingMutation),
    /NODE_PLACEMENT_SUBSTITUTION/,
  );

  const bundleMutation = fixture();
  bundleMutation.accessClasses.runtime.manifests.extra = { enabled: true };
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(bundleMutation),
    /BUNDLE_DIGEST/,
  );

  const associationMutation = fixture();
  associationMutation.accessClasses.bootstrap.podIdentityAssociationId =
    "standing-association";
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(associationMutation),
    /must equal null/,
  );

  const credentialMutation = fixture();
  credentialMutation.accessClasses.runtime.manifests.password = "forbidden";
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(credentialMutation),
    /forbidden credential material/,
  );

  for (const key of [
    "dbPassword",
    "clientSecret",
    "credentials",
    "apiKey",
    "dsn",
    "connectionString",
  ]) {
    const mutation = fixture();
    mutation.accessClasses.runtime.manifests[key] = "forbidden";
    assert.throws(
      () => parseAwsDatabaseInfrastructureHandoff(mutation),
      /CREDENTIAL_MATERIAL/,
      key,
    );
  }

  const secretManifest = fixture();
  secretManifest.accessClasses.runtime.manifests.extra = {
    apiVersion: "v1",
    kind: "Secret",
    data: { password: "Zm9yYmlkZGVu" },
  };
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(secretManifest),
    /CREDENTIAL_MATERIAL/,
  );

  const undefinedMutation = fixture();
  undefinedMutation.accessClasses.runtime.manifests.extra = {
    hidden: undefined,
  };
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(undefinedMutation),
    /JSON_DOMAIN/,
  );

  const nonFiniteMutation = fixture();
  nonFiniteMutation.accessClasses.runtime.manifests.extra = Number.NaN;
  assert.throws(
    () => parseAwsDatabaseInfrastructureHandoff(nonFiniteMutation),
    /JSON_DOMAIN/,
  );
});
