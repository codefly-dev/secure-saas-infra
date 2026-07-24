import { PolicyPack } from "@pulumi/policy";
import { resourcePolicies } from "./index";
import { stackPolicies } from "./stackRules";

// Pulumi's policy host loads the configured module with require(). Registration
// must therefore be an unconditional entrypoint side effect. Keep policy
// callbacks in side-effect-free modules so unit fixtures can import them.
new PolicyPack("secure-saas-infra-guardrails", {
  enforcementLevel: "mandatory",
  policies: [...resourcePolicies, ...stackPolicies],
});
