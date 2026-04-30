import * as aws from "@pulumi/aws";
import { SecurityConfig, baseTags, named } from "./config";

export function createAccountSecurityBaseline(config: SecurityConfig) {
  if (config.enableGuardDuty) {
    new aws.guardduty.Detector(named("guardduty"), {
      enable: true,
      tags: tag("guardduty"),
    });
  }

  if (config.enableSecurityHub) {
    new aws.securityhub.Account(named("securityhub"), {
      enableDefaultStandards: true,
    });
  }
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
