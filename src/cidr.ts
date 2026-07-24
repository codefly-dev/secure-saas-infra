export interface ParsedCidr {
  cidr: string;
  networkAddress: number;
  broadcastAddress: number;
  prefix: number;
}

function ipToNumber(ip: string): number {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address '${ip}'.`);
  }

  const octets = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      throw new Error(`Invalid IPv4 address '${ip}'.`);
    }
    const octet = Number(part);
    if (octet < 0 || octet > 255) {
      throw new Error(`Invalid IPv4 address '${ip}'.`);
    }
    return octet;
  });

  return octets.reduce((acc, octet) => (acc * 256 + octet) >>> 0, 0);
}

function numberToIp(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

export function cidrSubnet(
  baseCidr: string,
  newBits: number,
  netNum: number,
): string {
  const parsed = parseCidr(baseCidr);
  if (!Number.isInteger(newBits) || newBits < 0) {
    throw new Error(`newBits must be a non-negative integer for ${baseCidr}.`);
  }
  if (!Number.isInteger(netNum) || netNum < 0) {
    throw new Error(`netNum must be a non-negative integer for ${baseCidr}.`);
  }

  const prefix = parsed.prefix;
  const newPrefix = prefix + newBits;

  if (newPrefix > 32) {
    throw new Error(`Invalid subnet prefix ${newPrefix} for ${baseCidr}`);
  }

  const availableSubnets = 2 ** newBits;
  if (netNum >= availableSubnets) {
    throw new Error(
      `Subnet number ${netNum} is outside ${baseCidr}; expected less than ${availableSubnets}.`,
    );
  }

  const subnetSize = 2 ** (32 - newPrefix);
  const subnetBase = parsed.networkAddress + subnetSize * netNum;

  return `${numberToIp(subnetBase)}/${newPrefix}`;
}

export function parseCidr(value: string): ParsedCidr {
  const parts = value.split("/");
  if (parts.length !== 2 || !/^\d{1,2}$/.test(parts[1])) {
    throw new Error(`Invalid IPv4 CIDR '${value}'.`);
  }

  const address = ipToNumber(parts[0]);
  const prefix = Number(parts[1]);
  if (prefix < 0 || prefix > 32) {
    throw new Error(`Invalid IPv4 CIDR prefix '${value}'.`);
  }

  const hostBits = 32 - prefix;
  const size = 2 ** hostBits;
  const networkAddress = Math.floor(address / size) * size;
  if (address !== networkAddress) {
    throw new Error(
      `IPv4 CIDR '${value}' is not aligned to its network boundary.`,
    );
  }

  return {
    cidr: `${numberToIp(networkAddress)}/${prefix}`,
    networkAddress,
    broadcastAddress: networkAddress + size - 1,
    prefix,
  };
}

export function cidrsOverlap(left: string, right: string): boolean {
  const a = parseCidr(left);
  const b = parseCidr(right);
  return (
    a.networkAddress <= b.broadcastAddress &&
    b.networkAddress <= a.broadcastAddress
  );
}
