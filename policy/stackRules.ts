import type { PolicyResource, StackValidationPolicy } from "@pulumi/policy";

const types = {
  vpc: "aws:ec2/vpc:Vpc",
  flowLog: "aws:ec2/flowLog:FlowLog",
  dnsAssociation:
    "aws:route53/resolverQueryLogConfigAssociation:ResolverQueryLogConfigAssociation",
  bucket: "aws:s3/bucket:Bucket",
  publicAccessBlock: "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
  bucketEncryption:
    "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
  bucketVersioning: "aws:s3/bucketVersioning:BucketVersioning",
  bucketVersioningV2: "aws:s3/bucketVersioningV2:BucketVersioningV2",
  firewall: "aws:networkfirewall/firewall:Firewall",
  firewallLogging:
    "aws:networkfirewall/loggingConfiguration:LoggingConfiguration",
  routeTable: "aws:ec2/routeTable:RouteTable",
  route: "aws:ec2/route:Route",
  internetGateway: "aws:ec2/internetGateway:InternetGateway",
  natGateway: "aws:ec2/natGateway:NatGateway",
  subnet: "aws:ec2/subnet:Subnet",
} as const;

export const stackPolicies: StackValidationPolicy[] = [
  {
    name: "vpcs-bind-flow-and-dns-query-logging",
    description:
      "Every VPC must be linked through Pulumi property dependencies to flow and Route 53 Resolver query logging.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      for (const vpc of resourcesOfType(args.resources, types.vpc)) {
        if (!hasDependent(args.resources, types.flowLog, "vpcId", vpc)) {
          reportViolation(
            "VPC is missing its exact Flow Log relationship.",
            vpc.urn,
          );
        }
        if (
          !hasDependent(args.resources, types.dnsAssociation, "resourceId", vpc)
        ) {
          reportViolation(
            "VPC is missing its exact DNS query-log association.",
            vpc.urn,
          );
        }
      }
    },
  },
  {
    name: "s3-buckets-bind-security-companions",
    description:
      "Every S3 bucket must bind public-access blocking and CMK encryption; data/evidence buckets must also bind versioning.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      for (const bucket of resourcesOfType(args.resources, types.bucket)) {
        if (
          !hasDependent(
            args.resources,
            types.publicAccessBlock,
            "bucket",
            bucket,
          )
        ) {
          reportViolation(
            "S3 bucket is missing its exact public-access-block relationship.",
            bucket.urn,
          );
        }
        if (
          !hasDependent(
            args.resources,
            types.bucketEncryption,
            "bucket",
            bucket,
          )
        ) {
          reportViolation(
            "S3 bucket is missing its exact CMK-encryption relationship.",
            bucket.urn,
          );
        }
        if (
          requiresVersioning(bucket) &&
          !hasEnabledVersioning(args.resources, bucket)
        ) {
          reportViolation(
            "Data or evidence S3 bucket is missing its exact versioning relationship.",
            bucket.urn,
          );
        }
      }
    },
  },
  {
    name: "network-firewalls-bind-flow-and-alert-logging",
    description:
      "Every Network Firewall must have one dependency-bound logging configuration that emits FLOW and ALERT logs.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      for (const firewall of resourcesOfType(args.resources, types.firewall)) {
        const logging = args.resources.find(
          (resource) =>
            resource.type === types.firewallLogging &&
            propertyDependsOn(resource, "firewallArn", firewall),
        );
        const logTypes = new Set(
          (
            logging?.props.loggingConfiguration?.logDestinationConfigs ?? []
          ).map((entry: { logType?: string }) => entry.logType),
        );
        if (!logging || !logTypes.has("FLOW") || !logTypes.has("ALERT")) {
          reportViolation(
            "Network Firewall is missing dependency-bound FLOW and ALERT logging.",
            firewall.urn,
          );
        }
      }
    },
  },
  {
    name: "confidential-resources-bind-evidence-sinks",
    description:
      "Confidential data resources must carry the immutable evidence-sink identity proven by the cloud-neutral blueprint compiler.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      for (const resource of args.resources) {
        const classification = tags(resource).DataClass;
        if (
          ![
            "confidential",
            "regulated",
            "platform-database",
            "customer-code",
            "secrets-backup",
          ].includes(classification ?? "")
        ) {
          continue;
        }
        if (tags(resource).EvidenceSinkId !== "audit-log") {
          reportViolation(
            "Confidential resource is not bound to the reviewed audit-log evidence sink.",
            resource.urn,
          );
        }
      }
    },
  },
  {
    name: "private-spoke-default-routes-use-transit-gateway",
    description:
      "Every private-spoke route table must default only to Transit Gateway, never directly to NAT or an Internet Gateway.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      for (const table of resourcesOfType(args.resources, types.routeTable)) {
        if (tags(table).NetworkRole !== "private-spoke") continue;
        const ipv4Defaults = args.resources.filter(
          (resource) =>
            resource.type === types.route &&
            resource.props.destinationCidrBlock === "0.0.0.0/0" &&
            propertyDependsOn(resource, "routeTableId", table),
        );
        const ipv6Defaults = args.resources.filter(
          (resource) =>
            resource.type === types.route &&
            resource.props.destinationIpv6CidrBlock === "::/0" &&
            propertyDependsOn(resource, "routeTableId", table),
        );
        if (
          ipv4Defaults.length !== 1 ||
          !isTransitOnlyDefault(ipv4Defaults[0]) ||
          ipv6Defaults.length > 1 ||
          ipv6Defaults.some((route) => !isTransitOnlyDefault(route))
        ) {
          reportViolation(
            "Private-spoke route table defaults must use only Transit Gateway for IPv4 and IPv6.",
            table.urn,
          );
        }
      }
    },
  },
  {
    name: "internet-gateways-bind-central-egress-vpc",
    description:
      "Internet and NAT Gateways must be dependency-bound to a VPC tagged as the centralized egress boundary.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      for (const gateway of args.resources) {
        if (gateway.type === types.internetGateway) {
          const vpc = propertyTargets(gateway, "vpcId").find(
            (resource) => resource.type === types.vpc,
          );
          if (!vpc || tags(vpc).NetworkRole !== "central-egress") {
            reportViolation(
              "Internet Gateway is not dependency-bound to the central-egress VPC.",
              gateway.urn,
            );
          }
        }
        if (gateway.type === types.natGateway) {
          const subnet = propertyTargets(gateway, "subnetId").find(
            (resource) => resource.type === types.subnet,
          );
          const vpc = subnet
            ? propertyTargets(subnet, "vpcId").find(
                (resource) => resource.type === types.vpc,
              )
            : undefined;
          if (!vpc || tags(vpc).NetworkRole !== "central-egress") {
            reportViolation(
              "NAT Gateway is not dependency-bound through a subnet to the central-egress VPC.",
              gateway.urn,
            );
          }
        }
      }
    },
  },
];

function resourcesOfType(
  resources: readonly PolicyResource[],
  type: string,
): PolicyResource[] {
  return resources.filter((resource) => resource.type === type);
}

function hasDependent(
  resources: readonly PolicyResource[],
  types: string | readonly string[],
  property: string,
  target: PolicyResource,
): boolean {
  const allowed = new Set(Array.isArray(types) ? types : [types]);
  return resources.some(
    (resource) =>
      allowed.has(resource.type) &&
      propertyDependsOn(resource, property, target),
  );
}

function propertyDependsOn(
  resource: PolicyResource,
  property: string,
  target: PolicyResource,
): boolean {
  return propertyTargets(resource, property).some(
    (dependency) => dependency.urn === target.urn,
  );
}

function propertyTargets(
  resource: PolicyResource,
  property: string,
): PolicyResource[] {
  return resource.propertyDependencies?.[property] ?? [];
}

function hasEnabledVersioning(
  resources: readonly PolicyResource[],
  bucket: PolicyResource,
): boolean {
  return resources.some(
    (resource) =>
      [types.bucketVersioning, types.bucketVersioningV2].includes(
        resource.type as typeof types.bucketVersioning,
      ) &&
      propertyDependsOn(resource, "bucket", bucket) &&
      resource.props.versioningConfiguration?.status === "Enabled",
  );
}

function isTransitOnlyDefault(route: PolicyResource): boolean {
  return (
    Boolean(route.props.transitGatewayId) &&
    !route.props.natGatewayId &&
    !route.props.gatewayId &&
    !route.props.egressOnlyGatewayId &&
    !route.props.networkInterfaceId &&
    !route.props.vpcPeeringConnectionId
  );
}

function tags(resource: PolicyResource): Record<string, string | undefined> {
  const value = resource.props.tags;
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
}

function requiresVersioning(resource: PolicyResource): boolean {
  const value = tags(resource);
  return (
    value.VersioningRequired === "true" ||
    exactIdentifier(value.DataClass) ||
    exactIdentifier(value.EvidenceClass)
  );
}

function exactIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(value)
  );
}
