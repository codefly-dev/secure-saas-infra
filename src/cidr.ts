function ipToNumber(ip: string): number {
  return ip
    .split(".")
    .map((part) => Number.parseInt(part, 10))
    .reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0;
}

function numberToIp(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

export function cidrSubnet(baseCidr: string, newBits: number, netNum: number): string {
  const [baseIp, prefixRaw] = baseCidr.split("/");
  const prefix = Number.parseInt(prefixRaw, 10);
  const newPrefix = prefix + newBits;

  if (newPrefix > 32) {
    throw new Error(`Invalid subnet prefix ${newPrefix} for ${baseCidr}`);
  }

  const subnetSize = 2 ** (32 - newPrefix);
  const base = ipToNumber(baseIp);
  const subnetBase = (base + subnetSize * netNum) >>> 0;

  return `${numberToIp(subnetBase)}/${newPrefix}`;
}
