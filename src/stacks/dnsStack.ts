import { DnsConfig } from "../config";
import { createDns } from "../dns";

export function createDnsStack(config: DnsConfig) {
  return createDns(config);
}
