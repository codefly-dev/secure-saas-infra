import { PolicyPack } from "@pulumi/policy";
import { managementSeedPolicies } from "./managementSeed";

new PolicyPack("secure-saas-management-seed-guardrails", {
  enforcementLevel: "mandatory",
  policies: managementSeedPolicies,
});
