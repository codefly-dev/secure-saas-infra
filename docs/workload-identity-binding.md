# Exact workload identity binding

`WorkloadIdentityBinding v1alpha1` is the IaC-owned companion contract that
selects one workload identity. It does not expand `CloudContext v1alpha1`'s
aggregate identity allowlist and therefore does not break that frozen wire
contract.

The checked contract binds all of these dimensions together:

- organization, platform tenant, application, and environment;
- cloud context ID and generation;
- Kubernetes cluster UID, namespace, and ServiceAccount;
- exact Kubernetes ServiceAccount subject and SPIFFE ID;
- exact cloud role, audience, and bounded session duration;
- exact allowed infrastructure resource identities;
- one strict workload network attachment; and
- content-addressed verification evidence.

`administrator: false`, `shared: false`, and
`automountServiceAccountToken: false` are literals, not caller preferences.
Catalog validation rejects reuse of a binding ID, Kubernetes subject,
cluster/namespace/ServiceAccount tuple, cloud role, or provider network
boundary. Placement resolves all ownership dimensions and must select exactly
one binding.

## AWS compilation

The AWS adapter joins the binding to the existing IAM compiler output. It
fails unless exactly one EKS Pod Identity association has the same identity
ID, role ARN, namespace, ServiceAccount, and `pods.eks.amazonaws.com` audience;
exactly one trust policy has the same session duration; and exactly one identity
policy owns the same resource-ID set. The canonical Kubernetes subject remains
part of the provider-neutral binding digest, but it is not used as an AWS OIDC
trust principal.

Successful compilation emits:

1. a ServiceAccount with the general Kubernetes API token automount disabled
   and exact neutral audience/binding/mode/role metadata, but no IRSA role
   annotation;
2. an exact EKS Pod Identity namespace/ServiceAccount-to-role association;
3. a unique binding label on that ServiceAccount; and
4. an EKS Auto Mode `NodeClass` network-attachment requirement identifying one
   exact Pod security group and requiring a dedicated scheduling boundary.

EKS Auto Mode does not support the VPC CNI `SecurityGroupPolicy` mechanism.
The AWS realization therefore uses a dedicated `NodeClass` and `NodePool` for
each network access class. `podSubnetSelectorTerms` and
`podSecurityGroupSelectorTerms` attach the exact Pod security group to every Pod
on those nodes; a unique label plus `NoSchedule` taint forces the workload to
opt into that class with an exact selector and toleration. The NodeClass also
uses `DefaultDeny` network policy mode, event logging, private-address-only
nodes, and explicit private subnets. AWS documents both the Auto Mode
[NodeClass Pod-network mechanism](https://docs.aws.amazon.com/eks/latest/userguide/create-node-class.html)
and the corresponding
[NodePool scheduling contract](https://docs.aws.amazon.com/eks/latest/userguide/create-node-pool.html).

## Validation boundary

The JSON Schema, checked fixture, handwritten parser, canonicalizer, and owner
are registered in the active IaC contract registry. The generated
schema-rejection corpus deletes every reachable required field, injects fields
into closed objects, and mutates schema bounds. Focused semantic tests cover
namespace, ServiceAccount, canonical subject, SPIFFE ID, audience, tenant,
environment, role, resource, network, and session substitutions.

The binding digest detects changes to any bound field. The referenced
verification evidence is not yet redeemed against a production trust store by
this contract alone; signed evidence redemption and persistent replay/revocation
state remain part of EVD-001. Disposable K3s proves that a manually submitted,
EKS-shaped token projection is admitted and its substitutions are denied; it
does not prove that EKS injected the projection and cannot emulate the EKS Pod
Identity Agent. Runtime proof that EKS injected credentials, admitted the Auto
Mode NodeClass/NodePool and `ApplicationNetworkPolicy`, provisioned the
dedicated nodes/Pod ENIs, enforced the Pod security group, and authorized
STS/RDS stays open until the AWS-dev probes pass.
