import test from "node:test";
import assert from "node:assert/strict";
import { cidrSubnet, cidrsOverlap, parseCidr } from "../src/cidr";

test("cidrSubnet derives deterministic non-overlapping subnets", () => {
  assert.equal(cidrSubnet("10.0.0.0/16", 8, 0), "10.0.0.0/24");
  assert.equal(cidrSubnet("10.0.0.0/16", 8, 1), "10.0.1.0/24");
  assert.equal(cidrSubnet("10.0.0.0/16", 8, 16), "10.0.16.0/24");
});

test("cidrSubnet rejects impossible prefix expansion", () => {
  assert.throws(() => cidrSubnet("10.0.0.0/30", 4, 0), /Invalid subnet prefix/);
});

test("CIDR utilities reject malformed, unaligned, and out-of-parent allocations", () => {
  assert.throws(() => parseCidr("10.0.999.0/24"), /Invalid IPv4/);
  assert.throws(() => parseCidr("10.0.1.0/16"), /not aligned/);
  assert.throws(() => cidrSubnet("10.0.0.0/16", 8, 256), /outside/);
  assert.throws(() => cidrSubnet("10.0.0.0/16", -1, 0), /newBits/);
});

test("cidrsOverlap detects nested and disjoint networks", () => {
  assert.equal(cidrsOverlap("10.0.0.0/16", "10.0.2.0/24"), true);
  assert.equal(cidrsOverlap("10.0.0.0/16", "10.1.0.0/16"), false);
});
