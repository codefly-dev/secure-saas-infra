import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("public WAF web ACL has rate limiting, managed rule sets, bot control, and a model-gateway sub-rate limit", async () => {
  const { resources } = await installPulumiMocks();
  const { createPublicWebAcl } = await import("../src/waf");

  createPublicWebAcl({
    name: "public-ingress",
    scope: "REGIONAL",
    rateLimitPer5Minutes: 2000,
    enableBotControl: true,
    modelGatewayPathPrefixes: ["/v1/models", "/v1/agents"],
    modelGatewayRateLimitPer5Minutes: 200,
  });

  await flushPulumiMocks();

  const webAcl = resourcesOfType(resources, "aws:wafv2/webAcl:WebAcl")[0];
  assert.ok(webAcl);
  assert.equal(webAcl.inputs.scope, "REGIONAL");
  assert.equal(webAcl.inputs.defaultAction.allow !== undefined, true);
  assert.equal(webAcl.inputs.visibilityConfig.cloudwatchMetricsEnabled, true);

  const rules = webAcl.inputs.rules as Array<Record<string, any>>;
  const rateRule = rules.find(
    (rule) =>
      rule.statement?.rateBasedStatement &&
      !rule.statement.rateBasedStatement.scopeDownStatement,
  );
  assert.ok(rateRule);
  assert.equal(rateRule.statement.rateBasedStatement.limit, 2000);

  const modelRule = rules.find(
    (rule) =>
      rule.statement?.rateBasedStatement?.scopeDownStatement
        ?.regexMatchStatement,
  );
  assert.ok(modelRule);
  assert.equal(modelRule.statement.rateBasedStatement.limit, 200);

  const managed = rules.filter(
    (rule) => rule.statement?.managedRuleGroupStatement,
  );
  const managedNames = managed.map(
    (rule) => rule.statement.managedRuleGroupStatement.name,
  );
  assert.ok(managedNames.includes("AWSManagedRulesCommonRuleSet"));
  assert.ok(managedNames.includes("AWSManagedRulesKnownBadInputsRuleSet"));
  assert.ok(managedNames.includes("AWSManagedRulesAmazonIpReputationList"));
  assert.ok(managedNames.includes("AWSManagedRulesAnonymousIpList"));
  assert.ok(managedNames.includes("AWSManagedRulesBotControlRuleSet"));

  const logging = resourcesOfType(
    resources,
    "aws:wafv2/webAclLoggingConfiguration:WebAclLoggingConfiguration",
  );
  assert.equal(logging.length, 1);
  assert.deepEqual(
    logging[0].inputs.redactedFields.map(
      (entry: { singleHeader: { name: string } }) => entry.singleHeader.name,
    ),
    ["authorization", "cookie", "x-api-key"],
  );

  const logGroup = resourcesOfType(
    resources,
    "aws:cloudwatch/logGroup:LogGroup",
  )[0];
  assert.equal(logGroup.inputs.retentionInDays, 365);
});
