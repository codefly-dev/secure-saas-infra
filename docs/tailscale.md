# Tailscale Access Pattern

Tailscale replaces bastion hosts in this architecture.

## Default Use

Use Tailscale for:

- Operator access to private Kubernetes APIs.
- Private access to internal platform services.
- Emergency access to execution infrastructure when explicitly approved.
- Site-to-site style access to private platform CIDRs through Tailscale `Connector` resources.

Do not use Tailscale as the normal internet egress path for client code. Client-code egress must stay on the centralized egress VPC path so traffic can be inspected, logged, and policy-controlled.

## Kubernetes Operator

Install the Tailscale Kubernetes Operator with the official Helm chart. The operator requires OAuth credentials with `Devices Core`, `Auth Keys`, and `Services` write scopes and the `tag:k8s-operator` tag.

The platform repository's
[`tailscale-operator.application.yaml`](https://github.com/codefly-dev/secure-saas-platform/blob/v0.1.0/gitops/bootstrap/argocd/base/apps/tailscale-operator.application.yaml)
installs the operator chart. Before syncing it, provide credentials through one
of these methods:

- Vault-backed secret injection into the `tailscale` namespace.
- Argo CD secret management plugin.
- Tailscale workload identity federation, once validated for the cluster.

Do not commit OAuth client secrets.

## Tailnet Policy

Start from `tailscale/policy.example.hujson`.

Required tag ownership:

- `tag:k8s-operator` owns operator-created tags.
- `tag:k8s-platform` is used for normal platform/admin access.
- `tag:k8s-execution-breakglass` is reserved for emergency execution-plane access.

## Platform Connector

The platform repository's
[`tailscale-platform-access.yaml`](https://github.com/codefly-dev/secure-saas-platform/blob/v0.1.0/gitops/clusters/platform/tailscale-platform-access.yaml)
advertises the platform VPC CIDR through a highly available Tailscale Connector:

```yaml
subnetRouter:
  advertiseRoutes:
    - 10.10.0.0/16
```

In production, routes should be approved automatically only for tightly controlled tags. Execution CIDRs should not be advertised by default.

## Why This Replaces Bastions

Bastion hosts add SSH exposure, patching burden, session management work, and credential sprawl. Tailscale gives identity-aware private access without public inbound SSH. AWS Security Groups should still deny public SSH/RDP everywhere.
