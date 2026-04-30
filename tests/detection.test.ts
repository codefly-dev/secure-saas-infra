import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("detection stack creates SNS topic and EventBridge rules for high-severity events", async () => {
  const { resources } = await installPulumiMocks();
  const { createDetectionRules } = await import("../src/detection");

  createDetectionRules({
    emailSubscriptions: ["security-alerts@deus.example"],
  });

  await flushPulumiMocks();

  const topic = resourcesOfType(resources, "aws:sns/topic:Topic")[0];
  assert.ok(topic);
  assert.match(topic.inputs.kmsMasterKeyId, /^alias\/aws\/sns$/);

  const subscriptions = resourcesOfType(
    resources,
    "aws:sns/topicSubscription:TopicSubscription",
  );
  assert.equal(subscriptions.length, 1);
  assert.equal(subscriptions[0].inputs.endpoint, "security-alerts@deus.example");

  const rules = resourcesOfType(
    resources,
    "aws:cloudwatch/eventRule:EventRule",
  );
  const ruleNames = rules.map((rule) => rule.inputs.name);
  for (const expected of [
    "guardduty-high-severity",
    "iam-identity-center-breakglass",
    "kms-rotation-disabled",
    "cloudtrail-mutations",
    "iam-user-or-key-creation",
    "config-noncompliant-resource",
    "securityhub-critical-finding",
  ]) {
    assert.ok(
      ruleNames.some((name) => String(name).includes(expected)),
      `expected event rule for ${expected}`,
    );
  }

  const targets = resourcesOfType(
    resources,
    "aws:cloudwatch/eventTarget:EventTarget",
  );
  assert.equal(targets.length, rules.length);
});
