import test from "node:test";
import assert from "node:assert/strict";
import {
  blueprintFromAwsNetworkConfig,
  validateAwsSpokeStackOutputs,
  validateAndCompileAwsNetwork,
} from "../src/adapters/aws";
import { evaluateBlueprint } from "../src/core";
import type { NetworkConfig } from "../src/config";

function networkConfig(): NetworkConfig {
  return {
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 3,
      networkFirewallEnabled: true,
      shareTransitGatewayWithOrganization: true,
      allowedDomains: ["github.com", "api.github.com"],
    },
    spokes: [
      {
        name: "platform",
        cidr: "10.10.0.0/16",
        kind: "platform",
        createEks: true,
      },
      {
        name: "execution",
        cidr: "10.20.0.0/16",
        kind: "execution",
        createEks: true,
      },
    ],
  };
}

test("AWS adapter round-trips existing network configuration through neutral intent", () => {
  const config = networkConfig();
  const plan = validateAndCompileAwsNetwork(config, {
    name: "production-network",
    environment: "production",
    requireInspectedEgress: true,
  });
  assert.deepEqual(plan.networkConfig, config);
  assert.equal(plan.zoneToSpokeName["zone:execution"], "execution");
  assert.equal(plan.spokes.length, 2);
  assert.deepEqual(
    plan.routeTableIntents
      .filter((route) => route.routeTableRole === "spoke-private")
      .map((route) => [route.destinationCidr, route.target]),
    [
      ["0.0.0.0/0", "transit-gateway"],
      ["0.0.0.0/0", "transit-gateway"],
    ],
  );
});

test("AWS semantic stack output validation rejects mismatched spokes", () => {
  assert.throws(
    () =>
      validateAwsSpokeStackOutputs(
        {
          zoneId: "zone:platform",
          networkDomainId: "network:platform",
          cidr: "10.10.0.0/16",
        },
        {
          zoneId: "zone:execution",
          networkDomainId: "network:execution",
          cidr: "10.20.0.0/16",
        },
      ),
    /semantic output mismatch/,
  );
});

test("AWS translation produces a provider-neutral blueprint with no policy violations", () => {
  const blueprint = blueprintFromAwsNetworkConfig(networkConfig(), {
    name: "production-network",
    environment: "production",
    requireInspectedEgress: true,
  });
  assert.deepEqual(evaluateBlueprint(blueprint), []);
  assert.equal(
    blueprint.trustZones.find((zone) => zone.id === "zone:execution")?.kind,
    "execution",
  );
});

test("AWS network validation rejects overlapping cloud networks before Pulumi", () => {
  const config = networkConfig();
  config.spokes = [
    ...config.spokes,
    { name: "overlap", cidr: "10.10.128.0/17", kind: "shared" },
  ];
  assert.throws(
    () =>
      validateAndCompileAwsNetwork(config, {
        name: "bad-network",
        environment: "development",
        requireInspectedEgress: false,
      }),
    /CORE_OVERLAPPING_CIDR/,
  );
});
