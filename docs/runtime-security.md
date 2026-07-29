# Runtime Security

GuardDuty Runtime Monitoring covers EKS at the AWS API level. For per-syscall
visibility, the GitOps baseline ships a Falco DaemonSet using the modern eBPF
driver.

## Falco

The platform repository's
[`falco.application.yaml`](https://github.com/codefly-dev/secure-saas-platform/blob/v0.1.0/gitops/bootstrap/argocd/base/apps/falco.application.yaml)
installs the Falco
chart with:

- `driver.kind: modern_ebpf` so no kernel modules are loaded.
- `falcoctl` artifact install for the `falco-rules`, `k8saudit-rules`, and
  `falco-incubating-rules` rule packs, with continuous follow.
- JSON output piped into `falcosidekick` for forwarding to CloudWatch
  (`/aws/falco/sandbox-events`) and the security tooling account.
- A DaemonSet across all worker nodes; the `falco` namespace is labelled
  `pod-security.kubernetes.io/enforce: privileged` so the privileged daemonset
  can run with minimum required Linux capabilities.

## Rules to watch

The default Falco rule set covers:

- Sandbox escape indicators (writes to `/proc`, kernel module load,
  unexpected `setuid`).
- Reverse shells and remote command execution.
- Sensitive file reads from inside containers.
- Privileged binary execution.
- Unexpected network connections from container processes.

The Mind-server-specific rules to add (custom Falco rules in a sidecar
ConfigMap):

- Container tries to read `169.254.169.254` (AWS metadata).
- Container writes to `/proc/sys/kernel/`.
- Process inside the `execution` namespace executes `iptables`, `nsenter`,
  `unshare`, or `kmod`.
- DNS query from `agent-egress` to a hostname not in `agenticAi.modelGatewayHostnames`.

## Relationship to other controls

- Kyverno in the
  [`gitops/base/kyverno`](https://github.com/codefly-dev/secure-saas-platform/tree/v0.1.0/gitops/base/kyverno)
  platform release enforces Pod Security `restricted`,
  RuntimeClass requirements, image signatures, and audit metadata at admission.
  Falco watches _runtime_ — a pod that passes admission but then misbehaves.
- VPC Flow Logs and Network Firewall ALERT logs cover network egress; Falco
  covers in-host syscalls.
- GuardDuty Runtime Monitoring stays enabled. The two systems complement each
  other: Falco's open ruleset is broader; GuardDuty has AWS-managed rules and
  feeds Security Hub directly.

## Operating

- Falcosidekick events route into CloudWatch logs in the workload account.
  Forward them to the `log-archive` account via subscription filter once the
  archive is wired up.
- The `detection` stack subscribes Security Hub critical findings and
  GuardDuty severity >= 7 events; Falco events should be added to that fan-out
  via Security Hub's custom-finding ingestion or via a CloudWatch Logs metric
  filter + alarm.
- Tune rules iteratively. Run Falco in `--dry-run` mode for the first week in
  a new environment to baseline noise before flipping to alerting.
