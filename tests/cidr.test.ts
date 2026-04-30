import test from "node:test";
import assert from "node:assert/strict";
import { cidrSubnet } from "../src/cidr";

test("cidrSubnet derives deterministic non-overlapping subnets", () => {
  assert.equal(cidrSubnet("10.0.0.0/16", 8, 0), "10.0.0.0/24");
  assert.equal(cidrSubnet("10.0.0.0/16", 8, 1), "10.0.1.0/24");
  assert.equal(cidrSubnet("10.0.0.0/16", 8, 16), "10.0.16.0/24");
});

test("cidrSubnet rejects impossible prefix expansion", () => {
  assert.throws(() => cidrSubnet("10.0.0.0/30", 4, 0), /Invalid subnet prefix/);
});
