import test from "node:test";
import assert from "node:assert/strict";
import { createReferenceBlueprint } from "../src/core";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("network routing binds semantic spoke outputs and creates cross-account return routes", async () => {
  const { resources } = await installPulumiMocks();
  const { createNetworkRoutingStack } =
    await import("../src/stacks/networkRoutingStack");
  const stackRef = "org/secure-saas-infra/execution-shared-net";
  createNetworkRoutingStack(
    {
      networkStackRef: "org/secure-saas-infra/network",
      spokeStackRefs: [stackRef],
      spokeBindings: [
        {
          stackRef,
          zoneId: "execution-shared",
          networkDomainId: "execution-shared-net",
        },
      ],
      azCount: 3,
      networkFirewallEnabled: true,
    },
    createReferenceBlueprint("pooled"),
  );

  await flushPulumiMocks();
  const accepters = resourcesOfType(
    resources,
    "aws:ec2transitgateway/vpcAttachmentAccepter:VpcAttachmentAccepter",
  );
  const tgwRoutes = resourcesOfType(
    resources,
    "aws:ec2transitgateway/route:Route",
  );
  const vpcRoutes = resourcesOfType(resources, "aws:ec2/route:Route");
  assert.equal(accepters.length, 1);
  assert.equal(
    accepters[0].inputs.transitGatewayAttachmentId,
    "tgw-attach-spoke",
  );
  assert.ok(
    tgwRoutes.some(
      (route) => route.inputs.destinationCidrBlock === "10.10.0.0/16",
    ),
  );
  assert.equal(vpcRoutes.length, 6);
});

test("network routing rejects duplicate bindings that leave a stack unbound", async () => {
  await installPulumiMocks();
  const { createNetworkRoutingStack } =
    await import("../src/stacks/networkRoutingStack");
  const first = "org/secure-saas-infra/first";
  const second = "org/secure-saas-infra/second";
  assert.throws(
    () =>
      createNetworkRoutingStack(
        {
          networkStackRef: "org/secure-saas-infra/network",
          spokeStackRefs: [first, second],
          spokeBindings: [
            {
              stackRef: first,
              zoneId: "execution-shared",
              networkDomainId: "execution-shared-net",
            },
            {
              stackRef: first,
              zoneId: "data-shared",
              networkDomainId: "data-shared-net",
            },
          ],
          azCount: 3,
          networkFirewallEnabled: true,
        },
        createReferenceBlueprint("pooled"),
      ),
    /each spoke stack reference exactly once/,
  );
});
