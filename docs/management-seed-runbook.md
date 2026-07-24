# AWS Organizations Management Seed

This release applies only the first AWS Organizations management-seed wave: the
Organization itself. A second wave can preview the ordered OUs, member-account
requests, deny-only SCP guardrails, native S3 Block Public Access policy, exact
trusted-service access, and RAM organization sharing, but cannot apply them
until scoped member access and immediate account-vending-role retirement are
qualified. It does not create EKS,
VPCs, databases, Kubernetes resources, Codefly resources, or application
deployments. Delegated administrators and every member-account wave are
post-seed work with separate roles and qualification.

## Trust boundaries

- Never use an IAM user or long-lived access key. AWS root is forbidden except
  for the single console-only ceremony documented below when a truly new
  account has no federation authority; root is forbidden again immediately
  after that ceremony.
- Preview and apply use distinct short-lived assumed roles, distinct existing
  pre-organization SAML source roles, checked-in policies, and matching permissions
  boundaries. Apply is seed-only: it explicitly denies policy updates, OU
  renames, delegated-admin registration, detach/delete, and other post-seed
  maintenance. It permits `organizations:MoveAccount` because the AWS provider
  creates a member account at the root before placing it under its reviewed OU;
  the immutable plan and exact topology constrain those moves operationally.
- The SAML apply source role can assume `OrganizationSeedApply` directly.
  Therefore the local signed-plan gate is an operational safety control, not a
  non-bypassable AWS four-eyes authorization boundary. Operators holding that
  assignment are trusted. A future non-bypassable model must remove human
  assume-role access and give only a controlled OIDC/CI broker authority to
  assume the apply role after independent approval.
- Provision the Ed25519 qualification key on a separate host/identity,
  HSM/KMS-backed signer, or protected signing service. Neither the
  qualification host nor the AWS execution host may access the private key.
- Use a dedicated Linux host with a qualification login, a separate human
  operator identity with digest-bound, argument-constrained `sudo` access only
  to the native `runtime-service` and plan-review export, and a locked
  `deus-runtime` system account. The
  system account has no home, login shell, password, or supplementary group and
  is never an operator login. The native launcher pins its UID/GID at seal time,
  requires the exact unified-cgroup-v2 one-shot systemd unit, rejects peers under
  that UID, and requires `kernel.yama.ptrace_scope` 2 or 3. It disables its own
  dumpability before reading a credential envelope from an anonymous pipe. Node
  receives separate scoped loopback broker capabilities; raw AWS and Pulumi
  secrets are never placed in Node's initial environment. End every
  qualification-account process before obtaining a credential.
- `/usr/local/bin/deus-aws-bootstrap` is the only credential-bearing
  entrypoint. Production preparation, sealing, and execution are Linux-only;
  Darwin builds are validation artifacts and cannot seal or carry credentials.
  The Linux launcher is a CGO-disabled static Go binary. It constructs an
  allowlisted environment before starting root-owned Node. Direct Node/npm
  commands are credential-free convenience commands, not a security boundary:
  a Node preload or npm hook can execute before a JavaScript guard.
- The signer trust, builtins-only verifier, Node runtime, tool closures, and
  qualified execution snapshot are root-owned and non-group/other-writable.
  Credentialed code is imported only from
  `/usr/local/lib/deus-bootstrap/execution`; there is no credentialed `--root`.
- Pulumi uses only the sealed
  `/usr/local/lib/deus-bootstrap/execution/artifacts/bootstrap-pulumi-home`.
  An inherited `PULUMI_HOME`, plugin cache, profile, proxy, custom CA, Node
  preload, or native loader variable is never forwarded.

## Credential-free preparation

The dedicated host procedure consumes an existing authenticated release tag;
it cannot create the host kit it must first verify. Before starting step 1,
land the reviewed source commit, create the single-parent disposition-only
child described in step 8, tag that child, and let the release workflow publish
the explicitly unqualified source release plus both provenanced host kits.
Production qualification begins only after one of those kits is authenticated
and installed on the dedicated native-Linux host.

1. Start with a disposable, dedicated Linux host. As the host administrator,
   create the qualification login and locked runtime service identity, then
   record their IDs:

   ```sh
   sudo useradd --create-home --user-group --shell /bin/bash deus-qualify
   sudo useradd --system --no-create-home --home-dir /nonexistent \
     --user-group --shell /usr/sbin/nologin deus-runtime
   sudo usermod --lock deus-runtime
   sudo groupadd --system deus-bootstrap-operators
   sudo usermod --append --groups deus-bootstrap-operators '<operator-login>'
   QUALIFICATION_UID="$(id -u deus-qualify)"
   QUALIFICATION_GID="$(id -g deus-qualify)"
   RUNTIME_UID="$(id -u deus-runtime)"
   RUNTIME_GID="$(id -g deus-runtime)"
   test "$QUALIFICATION_UID" != "$RUNTIME_UID"
   test "$(id -nG deus-runtime)" = deus-runtime
   getent passwd deus-runtime | \
     /bin/grep -E '^deus-runtime:[^:]*:[0-9]+:[0-9]+:[^:]*:/nonexistent:/(usr/)?sbin/nologin$'
   sudo getent shadow deus-runtime | /bin/grep -E '^deus-runtime:[!*]'
   ```

   Do not grant `deus-runtime` membership in `sudo`, `docker`, `adm`, or any
   other supplementary group. The launcher also checks the process's actual
   group vector and fails closed if account configuration later drifts.

   Do not run an installer, build script, JavaScript file, or launcher from a
   mutable checkout with `sudo`. Select an exact signed release tag and place
   its host-kit archive and host-kit provenance in `/trusted-downloads` by an
   operator-approved download process. The host image must already provide a
   root-owned SLSA verifier whose installation is trusted independently of this
   repository. Copy the untrusted downloads to a root-owned, non-writable
   staging directory first, then verify that copied archive against the exact
   repository identity and tag:

   ```sh
   RELEASE_TAG=v0.1.0
   RELEASE_REVISION='<40-hex-tagged-evidence-child-revision>'
   REVIEWED_SOURCE_REVISION='<40-hex-disposition-parent-revision>'
   case "$(uname -m)" in
     x86_64) RELEASE_ARCHITECTURE=amd64 ;;
     aarch64|arm64) RELEASE_ARCHITECTURE=arm64 ;;
     *) exit 64 ;;
   esac
   HOST_KIT="deus-bootstrap-host-kit-${RELEASE_TAG}-${RELEASE_ARCHITECTURE}"
   sudo /usr/bin/install -d -o root -g root -m 0755 \
     /var/lib/deus-bootstrap/stage0
   sudo /usr/bin/install -o root -g root -m 0444 \
     "/trusted-downloads/${HOST_KIT}.tar.gz" \
     "/var/lib/deus-bootstrap/stage0/${HOST_KIT}.tar.gz"
   sudo /usr/bin/install -o root -g root -m 0444 \
     "/trusted-downloads/deus-bootstrap-host-kit-${RELEASE_TAG}.intoto.jsonl" \
     "/var/lib/deus-bootstrap/stage0/deus-bootstrap-host-kit-${RELEASE_TAG}.intoto.jsonl"

   /usr/local/bin/slsa-verifier version | /bin/grep -F '2.7.1'
   VERIFIED_PROVENANCE="$HOME/deus-bootstrap-host-kit.verified-provenance.json"
   /usr/local/bin/slsa-verifier verify-artifact \
     "/var/lib/deus-bootstrap/stage0/${HOST_KIT}.tar.gz" \
     --provenance-path "/var/lib/deus-bootstrap/stage0/deus-bootstrap-host-kit-${RELEASE_TAG}.intoto.jsonl" \
     --source-uri github.com/codefly-dev/secure-saas-infra \
     --source-tag "$RELEASE_TAG" \
     --print-provenance > "$VERIFIED_PROVENANCE"

   /usr/bin/jq -e --arg revision "$RELEASE_REVISION" \
     '(.predicate.invocation.configSource.digest.sha1 == $revision) or
      any(.predicate.buildDefinition.resolvedDependencies[]?;
          .digest.gitCommit == $revision)' \
     "$VERIFIED_PROVENANCE"
   HOST_KIT_VERIFIER="$(mktemp "$HOME/deus-host-kit-verifier.XXXXXX")"
   trap 'rm -f "$HOST_KIT_VERIFIER"' EXIT HUP INT TERM
   /bin/tar -xOzf \
     "/var/lib/deus-bootstrap/stage0/${HOST_KIT}.tar.gz" \
     ./deus-aws-bootstrap > "$HOST_KIT_VERIFIER"
   chmod 0500 "$HOST_KIT_VERIFIER"
   "$HOST_KIT_VERIFIER" verify-host-kit-archive \
     --archive "/var/lib/deus-bootstrap/stage0/${HOST_KIT}.tar.gz" \
     --tag "$RELEASE_TAG" \
     --revision "$RELEASE_REVISION" \
     --architecture "$RELEASE_ARCHITECTURE"

   test ! -e "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}"
   sudo /usr/bin/install -d -o root -g root -m 0755 \
     "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}"
   sudo /bin/tar -xzf \
     "/var/lib/deus-bootstrap/stage0/${HOST_KIT}.tar.gz" \
     --no-overwrite-dir --delay-directory-restore \
     -C "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}"
   sudo /bin/chown -R root:root "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}"
   sudo /usr/bin/find "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}" \
     -type d -exec /bin/chmod 0755 {} \;
   sudo /usr/bin/find "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}" \
     -type f -exec /bin/chmod go-w {} \;
   (cd "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}" && \
     /usr/bin/sha256sum --strict --check SHA256SUMS)
   /bin/grep -Fx "releaseTag=${RELEASE_TAG}" \
     "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}/RELEASE"
   /bin/grep -Fx "sourceRevision=${RELEASE_REVISION}" \
     "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}/RELEASE"
   /bin/grep -Fx "architecture=${RELEASE_ARCHITECTURE}" \
     "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}/RELEASE"
   rm -f "$HOST_KIT_VERIFIER"
   trap - EXIT HUP INT TERM
   ```

   The host-kit has separate SLSA provenance and is built on a fresh release
   runner that never installs npm dependencies or Pulumi. Provenance verifies
   the released archive and its exact reviewed source/tag. Before any root
   extraction, the authenticated native verifier rejects extra/duplicate
   members, path traversal, links, devices/FIFOs, unsafe modes/owners/times,
   excessive sizes, trailing compressed data, identity drift, and checksum
   drift. `SHA256SUMS` then verifies every extracted privileged input after it
   is root-owned. The SLSA verifier, host
   OS tools, GitHub-hosted builder, pinned setup actions, and GitHub/Sigstore
   identity are explicit stage-zero trust dependencies.

   Configure process-inspection isolation before installing the runtime. This
   is an explicit host-administrator action, not something the IaC process may
   silently weaken or self-approve:

   ```sh
   printf '%s\n' 'kernel.yama.ptrace_scope = 2' | \
     sudo /usr/bin/tee /etc/sysctl.d/99-deus-bootstrap-ptrace.conf >/dev/null
   sudo /usr/sbin/sysctl --system
   test "$(cat /proc/sys/kernel/yama/ptrace_scope)" -ge 2
   ```

   Next place only operator-reviewed Linux tool archives in
   `/trusted-downloads`. The exact Go, Node, and Pulumi release archive
   filenames and SHA-256 values are pinned in the separately provenanced,
   authenticated kit's
   `security/bootstrap-host-toolchain.json`. The installer verifies the AWS CLI
   v2 signature against the pinned AWS CLI Team primary fingerprint. The
   provenance truthfully records Go/Node/Pulumi as authenticated-host-kit
   digest pins and does not claim a vendor signature for them. The installer
   rejects additional PGP primary keys, installs the complete Pulumi and AWS
   CLI closures, keeps npm in a separate qualification-only path, and emits a
   root-owned provenance record. Invoke only the verified, root-owned kit copy:

   ```sh
   sudo "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}/scripts/install-bootstrap-runtime" \
     --go-archive /trusted-downloads/go1.26.5.linux-<arch>.tar.gz \
     --node-archive /trusted-downloads/node-v24.18.0-linux-<arch>.tar.xz \
     --pulumi-archive /trusted-downloads/pulumi-v3.253.0-linux-<arch>.tar.gz \
     --aws-archive /trusted-downloads/awscli-exe-linux-<arch>-2.36.2.zip \
     --aws-signature /trusted-downloads/awscli-exe-linux-<arch>-2.36.2.zip.sig \
     --aws-public-key /trusted-downloads/aws-cli-team.asc
   ```

   Here `<arch>` means the filenames pinned for `amd64`/`arm64` in the
   manifest (`x64`/`x86_64`/`aarch64` where the vendor uses those spellings).
   Install Git `2.55.0` from a distribution-signed root-owned OS package at
   `/usr/bin/git`; Git is qualification-only and is not in the credentialed
   runtime inventory.

   Install only the already verified launcher from the same host kit. Do not
   build or install a checkout-produced launcher on the qualification host:

   ```sh
   sudo /usr/bin/install -o root -g root -m 0555 \
     "/var/lib/deus-bootstrap/stage0/${RELEASE_TAG}/deus-aws-bootstrap" \
     /usr/local/bin/deus-aws-bootstrap
   /usr/local/lib/deus-bootstrap/bin/node --version
   sudo /usr/local/bin/deus-aws-bootstrap install-sudoers
   sudo /usr/sbin/visudo -cf /etc/sudoers.d/deus-bootstrap-runtime
   ```

   Use a distinct host-administrator identity to install this policy. The
   operator login must not retain a second broad sudo rule. The policy binds
   the launcher SHA-256, exact command/argument regex, `NOSETENV`, and a
   command-scoped `!use_pty` setting so modern sudo cannot replace the
   anonymous credential pipe with a PTY. Reinstall the policy after every
   authenticated launcher update; the old digest intentionally stops matching.

   Qualification hashes the full Pulumi distribution, policy analyzer, AWS CLI
   install closure, Node, provider plugin, dependencies, and every explicitly
   invoked executable. Repository IaC code does not invoke Git or npm after an
   AWS session enters the launcher, and neither tool is in the credentialed
   executable inventory, and the credentialed `PATH` contains no host
   `/usr/bin` or `/bin`. Credentialed execution is a layered kernel boundary.
   Root starts one fixed transient system service with `NoExecPaths=/` and
   candidate-derived exact `ExecPaths`, a read-only filesystem except for the
   plan/output directories, invisible foreign processes, no capabilities,
   namespace creation denied, and mount plus `memfd_create` syscalls denied.
   This makes the writable isolated home and output paths non-executable and
   prevents an
   approved dynamic loader from executing an unapproved writable target. The
   unprivileged launcher then installs an inner fail-closed Landlock
   `EXECUTE | READ_FILE` policy. Exact Node, Pulumi, AWS CLI, provider, ELF
   loader, library, and native-addon dependencies are discovered without
   executing them, hashed into runtime provenance, and rechecked before every
   run. Shared libraries and native addons remain candidate-bound and
   root-owned. Landlock is not claimed to make every readable file unreadable;
   systemd's no-exec namespace closes the readable-home explicit-loader seam.
   Qualification-only npm and Go trees are removed irreversibly by
   `seal-execution`; credential startup refuses to run if any remain. This
   boundary prevents unapproved executable files/processes. It does not claim
   that no-exec alone can make approved Node incapable of malicious
   JavaScript; source review and the isolated signer boundary decide which
   JavaScript becomes a signed candidate.
   A host without cgroup v2, the required systemd sandbox features, Landlock
   ABI v1, or enabled Landlock fails closed.

   The released launcher embeds SHA-256 pins for the exact stage-1 verifier and public
   qualification trust document. `seal-execution` refuses to install either
   file when its bytes differ from those pins. Configure and review the public
   trust root before the final launcher build/install; changing it requires a
   fresh tagged host-kit release and root-owned installation.

2. Copy `onboarding.config.example.json` to ignored
   `onboarding.local.json` and replace every account/backend/role placeholder.
   `managementPreviewTrustedPrincipalArn` and
   `managementApplyTrustedPrincipalArn` must identify the two exact existing
   pre-organization SAML roles under `/deus/bootstrap-source/` in the
   management account. `managementBootstrapSamlProviderArn` must be the exact
   same-account `saml-provider/DeusBootstrap` provider used by those roles.
   `managementBootstrapSamlMetadataSha256` must be the non-placeholder,
   lowercase SHA-256 of the exact reviewed UTF-8 metadata document uploaded
   during the external foundation ceremony. The later governed observation
   verifies that the `SAMLMetadataDocument` returned by
   `iam:GetSAMLProvider` has that same digest. The bundle also binds an exact
   empty tag inventory, `Allowed` assertion-encryption mode, and empty provider
   private-key inventory. A metadata or encryption update that preserves the
   provider ARN therefore fails every governed live access attestation.
   These are not IAM Identity Center permission-set roles: organization account
   access does not exist before the Organization. Live attestation
   requires both source trusts to contain only that federated principal,
   `sts:AssumeRoleWithSAML` plus `sts:TagSession`, and the exact AWS SAML
   commercial-AWS SAML audience—no AWS or service principal is admitted. This
   release fails closed for GovCloud and China partitions; their Organizations
   policy types, quota regions, endpoints, and federation details require
   separately qualified variants.
   `managementProvisionerPrincipalArn` must identify the third exact SAML role
   under `/deus/bootstrap-source/`, activated at the upstream IdP only for the
   access change set. The bundle derives the fourth exact source role as
   `/deus/bootstrap-source/ManagementSeedRetirement`; pre-create it with only
   the rendered retirement policy and govern its IdP assignment independently.
   The fixed target roles are
   `OrganizationSeedPreview` and `OrganizationSeedApply`.
   `managementAccessRegion` is the fixed CloudFormation region and must equal
   `aws:region` in `Pulumi.management.yaml`; the fixed stack name is
   `deus-management-seed-access`.
3. Copy `Pulumi.management.yaml.example` to ignored
   `Pulumi.management.yaml`; set the exact management account and globally
   unique member-account emails. Keep `seedWave: organization-only` for the
   first separately reviewed preview and apply. The currently qualified seed is
   greenfield-only: `createOrganization` must remain `true`; existing
   Organizations fail closed until a discovery/import adapter is separately
   reviewed.
4. Log in to the selected Pulumi backend and initialize only the management
   stack without AWS credentials.
5. Install the exact provider into the repository-local plugin-only home:

   ```sh
   env -i HOME="$HOME" LANG=C PATH="$PATH" \
     mise exec -- ./scripts/prepare-bootstrap-plugins
   ```

6. Render the exact rootless access bundle without credentials:

   ```sh
   npm run bootstrap:access-bundle -- \
     --config onboarding.local.json \
     --output artifacts/management-seed-access-bundle.json \
     --template-output artifacts/management-seed-access.template.json
   ```

   The bundle is deterministic and content-addressed. Its `precreatedFoundation`
   section describes the exact two target roles and their two immutable managed
   permissions boundaries. Its inert CloudFormation template contains only two
   `AWS::IAM::RolePolicy` resources, which install the checked inline policies
   into those already-created roles. Each target role has the same checked
   policy both inline and as its maximum-permissions boundary, a one-hour
   session limit, retain-on-delete protection, and an exact same-account
   `aws:PrincipalArn` trust condition.
   Each boundary also has an explicit `Deny`/`NotAction` cap exactly equal to
   its allowlist, so unreviewed actions remain denied even if a same-account
   resource policy grants a role session directly.
   It also renders the exact `sts:AssumeRole` identity policy each trusted
   principal needs. The policy allows only its corresponding target,
   explicitly denies assuming every other role, and explicitly denies every
   other source action. Configure those policies on the corresponding
   pre-organization SAML source roles; an account principal in a trust policy
   delegates authority to the account but does not silently grant every
   identity permission to assume the role. Rendering makes no AWS call and
   never proves that either trusted principal exists or has its required
   identity policy.

7. Recompute the complete bundle and require the deployable template to match
   the governed policies and onboarding decisions exactly:

   ```sh
   npm run bootstrap:verify-access-bundle -- \
     --config onboarding.local.json \
     --bundle artifacts/management-seed-access-bundle.json \
     --template artifacts/management-seed-access.template.json
   ```

8. On the dedicated host, verify the already tagged seed scope and GO
   dispositions from all three adversarial reviewers. The release revision and
   its reviewed parent must be clean exact commits. Create the fixed
   credential-free working root, then populate it from that release revision:

   ```sh
   sudo /usr/local/bin/deus-aws-bootstrap prepare-execution \
     --qualification-uid "$QUALIFICATION_UID" \
     --qualification-gid "$QUALIFICATION_GID"
   sudo -iu deus-qualify /absolute/path/scripts/prepare-qualified-execution-root
   sudo -iu deus-qualify \
     sh -c 'cd /usr/local/lib/deus-bootstrap/execution && exec /bin/bash'
   ```

   The preparation script clones only the committed revision, copies the two
   ignored configurations, installs dependencies without lifecycle scripts,
   installs the exact AWS provider plugin, renders and verifies the access
   bundle, and creates empty plan/receipt output directories. It performs no
   AWS call.

   The disposition binds the Git revision, file bytes, executable modes, and a
   seven-day process-review window. Its reviewer names and timestamp are
   routing/process evidence, not cryptographic identities and not AWS
   authorization. The separately controlled Ed25519 candidate signature is the
   machine authorization boundary.

   The prerequisite release used two PRs/commits. The source PR ran
   `validate:source` and did not edit the disposition. After that source landed
   and reviewers approved its exact tree, one child commit changed only
   `security/adversarial-review-disposition.json`; the review-promotion workflow
   verified the topology, reran `validate:source` against the exact PR head, and
   emitted explicitly unqualified source-release evidence without a local-gate
   artifact. The tag was admissible only from that evidence-only child, and the
   tag and GitHub release did not constitute production bootstrap
   qualification. The promotion preserved that single-parent shape: the
   disposition remains one non-merge child of the reviewed source commit. A
   merge commit is deliberately rejected. After the authenticated host kit is
   installed on this dedicated Linux qualifier, use the fixed execution root
   to run `verify:all`; only that sealed-host path may emit
   production-qualified local-gate and release evidence.

   Record the two identities separately and prove the topology before tagging:

   ```sh
   REVIEWED_SOURCE_REVISION='<40-hex disposition source.revision>'
   RELEASE_REVISION='<40-hex evidence-only child to tag>'
   test "$REVIEWED_SOURCE_REVISION" != "$RELEASE_REVISION"
   test "$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse "${RELEASE_REVISION}^")" = \
     "$REVIEWED_SOURCE_REVISION"
   test "$(GIT_NO_REPLACE_OBJECTS=1 git rev-list --parents -n 1 \
     "$RELEASE_REVISION" | awk '{print NF}')" = 2
   test "$(GIT_NO_REPLACE_OBJECTS=1 git diff --name-only \
     "$REVIEWED_SOURCE_REVISION" "$RELEASE_REVISION")" = \
     security/adversarial-review-disposition.json
   test ! -e .git/info/grafts
   test ! -e .git/shallow
   test -z "$(GIT_NO_REPLACE_OBJECTS=1 git for-each-ref \
     --format='%(refname)' refs/replace/)"
   ```

   `REVIEWED_SOURCE_REVISION` is the reviewed parent recorded in the
   disposition. `RELEASE_REVISION` is the tagged evidence child recorded by
   SLSA provenance, the host-kit manifest, and `RELEASE`; never substitute one
   for the other.

9. With all cloud/token/profile/preload variables removed, qualify from that
   exact root:

   ```sh
   ./scripts/credential-free-qualification --config onboarding.local.json
   ```

The credential-bearing launcher later gives code an isolated temporary home,
sets AWS config and shared-credential files to `/dev/null`, disables EC2
metadata credentials, and never passes Pulumi tokens/passphrases to AWS CLI
children.
Its installed builtins-only verifier uses an independently installed public
trust root, authenticates the candidate, and verifies root ownership plus the
running Node, exact credentialed executables, source, dependencies, build,
policy output, complete AWS CLI install, and fixed Pulumi plugin home before
importing snapshot code. No Git, npm, or version probe runs with cloud/backend
credentials. Qualification emits an unsigned request and
`artifacts/bootstrap-candidate.payload`.

## Independent signing

Transfer the single confidential
`artifacts/bootstrap-signing-review-bundle.json` to the independent signer over
an authenticated channel. It contains the unsigned request and its
domain-separated payload plus the exact ignored onboarding/Pulumi configuration
bytes, runtime provenance, launcher, access bundle/template, local-gate and
release evidence, schema-validation report, and SBOM. Never ask the signer to
approve a bare digest or opaque configuration hashes.
There is intentionally no private-key generator in this repository. The signer
must independently fetch the reviewed commit into the same fixed path on a
separate credential-free Linux builder. It installs the same authenticated
host kit/runtime. The static native launcher starts a root-owned, builtins-only
stage zero from that kit. Stage zero rejects root and authenticates every
tracked checkout file and mode against the kit's release/source manifest. The
root-managed online preparation service receives no bundle or configuration.
It runs trusted `npm ci --ignore-scripts`, checksum-bound provider
installation, G0/G1, audit, and SBOM. It then purges every ignored output and
reconstructs only the exact build, policy, support, launcher, dependency, and
provider closure. systemd collects that cgroup; the root parent rejects any
remaining process for the dedicated signer UID, inventories every tracked and
generated path, and changes the whole checkout to root-owned/read-only. Only
after that irreversible one-shot transition does a second service remove
network access and receive a root-created, fully sealed anonymous memfd. The
verifier consumes configuration bytes from that descriptor; they are never
reconstructed in the checkout and the online phase cannot open the root-only
source file:

This is a reviewed-release boundary, not a malware sandbox for a knowingly
hostile approved commit. The authenticated launcher, stage zero, checkout
verifier, and lockfile-pinned dependencies are candidate release bytes, and
the review verifier receives the raw bundle descriptor. Independently inspect
those exact bytes before placing the bundle. Treat all signer stdout/stderr and
logs as confidential, never forward them to the execution host, and never
automatically issue a signature from process exit status. A separate human or
non-exportable signing policy must approve the verified payload; transfer only
the resulting detached signature.

```sh
sudo groupadd --system deus-bootstrap-signers
sudo usermod --append --groups deus-bootstrap-signers deus-qualify
sudo useradd --system --no-create-home --home-dir /nonexistent \
  --user-group --shell /usr/sbin/nologin deus-signer-runtime
sudo usermod --lock deus-signer-runtime
SIGNER_UID="$(id -u deus-signer-runtime)"
SIGNER_GID="$(id -g deus-signer-runtime)"
test "$(id -nG deus-signer-runtime)" = deus-signer-runtime
sudo getent shadow deus-signer-runtime | \
  /bin/grep -E '^deus-signer-runtime:[!*]'
test -z "$(pgrep -u deus-signer-runtime || true)"
sudo /usr/local/bin/deus-aws-bootstrap install-signer-sudoers
sudo /usr/sbin/visudo -cf /etc/sudoers.d/deus-bootstrap-signer
sudo /usr/bin/install -d -o root -g root -m 0700 /var/lib/deus-bootstrap
sudo /usr/bin/install -o root -g root -m 0400 \
  "$HOME/bootstrap-signing-review-bundle.json" \
  /var/lib/deus-bootstrap/signing-review-bundle.json
sudo /bin/chown -R deus-signer-runtime:deus-signer-runtime \
  /usr/local/lib/deus-bootstrap/execution
sudo /bin/chmod 0700 /usr/local/lib/deus-bootstrap/execution
sudo --non-interactive /usr/local/bin/deus-aws-bootstrap signing-review-service \
  --signer-uid "$SIGNER_UID" \
  --signer-gid "$SIGNER_GID"
test ! -e /var/lib/deus-bootstrap/signing-review-bundle.json
rm -f "$HOME/bootstrap-signing-review-bundle.json"
```

`deus-signer-runtime` is not the qualification login and must never have a
session, user manager, supplementary group, sudo rule, or long-lived process.
The root-held transaction lock serializes preparation, freezing, bundle load,
and review. A successful or failed freeze consumes that checkout; provision a
fresh authenticated signer checkout for every retry.
The root service consumes and durably unlinks its root-only bundle before the
offline review starts. Delete the transfer source immediately afterward; a
retained copy is confidential material, not an audit artifact.

The helper rejects an inexact role inventory, base64/digest substitution,
bundle/request/payload mismatch, different source tree, build or launcher,
invalid configuration, access-template drift, malformed gate/release evidence,
schema inventory drift, SBOM/package-lock drift, or any difference in the
complete pinned Node/Pulumi/AWS CLI/plugin/dependency closure and root-owned
runtime provenance. Successful automation is necessary but not sufficient
authorization to sign: human account/email/role/backend review and the
signer's independent approval policy still apply. Only then may it return the
raw 64-byte Ed25519 signature. No configuration, bundle, private key, or signer
credential returns to the execution host. Finalize as the qualification
account:

```sh
npm run bootstrap:finalize -- \
  --signature /trusted-transfer/bootstrap-candidate.sig
```

After finalization, leave the qualification session. From the distinct operator
login, terminate every qualification-UID process and prove the UID is empty
before invoking the root seal. The seal refuses to start otherwise:

```sh
sudo pkill -KILL -u deus-qualify || true
test -z "$(pgrep -u deus-qualify || true)"
sudo /usr/local/bin/deus-aws-bootstrap seal-execution \
  --qualification-uid "$QUALIFICATION_UID" \
  --qualification-gid "$QUALIFICATION_GID" \
  --runtime-uid "$RUNTIME_UID" \
  --runtime-gid "$RUNTIME_GID"
```

Sealing installs the verifier and public trust root into the OS-owned trust
domain, prunes Git, tests, support builds, transient signing material, and every
tracked path outside the positive management-seed scope. It rejects unexpected
or special files, escaping symlinks, excessive file counts, and per-file/total
byte limits. The remaining source and candidate-bound generated roots are
copied onto fresh inodes as `root:deus-runtime` with `0440/0550` access.
Qualification-only npm/Go is irreversibly removed; write access returns only to
the empty `artifacts/pulumi-plans` and `artifacts/runtime-output` directories.
Any later source, dependency, build, tool, evidence, configuration, or plugin
change fails verification.

The signed candidate is valid for at most 24 hours. Do not use the qualification
account again for this release.

Obtain every AWS/Pulumi session only in the separate human operator login. The
operator may create the native credential envelope, but must pipe it into
`sudo --non-interactive deus-aws-bootstrap runtime-service ...`. Never log in,
`su`, or run a shell as `deus-runtime`, and never use `sudo --preserve-env`.
The root parent never parses the envelope; systemd passes the original pipe to
the fixed locked runtime identity, and the child accepts only that anonymous
pipe after verifying its exact unit, UID/GID, group vector, and peer-free UID.

Do not place a private key path, private key, or signer credential on either
repository host.

## First real AWS boundary: independently establish the access foundation

The irreducible external prerequisite is an administrator establishing the
same-account `DeusBootstrap` SAML provider, the four exact locked source roles,
the empty `OrganizationSeedPreview` and `OrganizationSeedApply` target roles,
and three immutable managed permissions boundaries from an independently
governed IdP session. The target roles must already have their matching
preview/apply boundary and no inline or attached policy. The third boundary is
the deny-all provisioner-retirement boundary. This repository renders and
attests every exact trust, role, boundary, and policy shape, but it cannot
create the first federation authority using authority that does not yet exist.
Do not use an IAM user or access key.

### Truly greenfield account: one governed root-console ceremony

A new standalone AWS account initially has only its root user. In that one
case, a console-only root ceremony is an explicit external prerequisite, not a
repository command and not a reusable administration path. AWS recommends
federation for human access, protecting root with MFA, and avoiding root access
keys; a root user may register multiple MFA devices. See [AWS IAM security best
practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html),
[root-user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html),
and [secure access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/securing_access-keys.html).

Before the ceremony:

- require a change ticket, two-person approval, named operator and observer,
  fixed time window, and independently reviewed bundle digest;
- secure root with at least two separately held phishing-resistant hardware MFA
  devices and verify the account recovery email and phone controls;
- confirm that root has no access keys. Do not create one, use the CLI, use an
  SDK, open CloudShell, or copy root credentials to this repository host;
- hash the exact reviewed IdP metadata UTF-8 bytes locally, without a trailing
  newline, place that lowercase digest in
  `managementBootstrapSamlMetadataSha256`, then render and review the access
  bundle from those same bytes. Treat its SAML trust, four source-role policies,
  two target roles, two target boundaries, and deny-all retirement boundary as
  the complete allowlist.

During the ceremony, sign in to the AWS console as root and create only the
exact `DeusBootstrap` SAML provider, four `/deus/bootstrap-source/` roles, two
empty target roles, and three managed boundaries described by the reviewed
bundle. The provider must use `Allowed` assertion-encryption mode and have no
private keys or tags. Do not create an IAM user, access key,
general administrator role, or any resource outside that inventory. Sign out
as soon as the exact source roles can be assumed through the upstream IdP.

After signing out, activate the exact `managementProvisionerPrincipalArn`
assignment at the upstream IdP just in time, then assume its short-lived
federated session and run the governed `--observe-foundation` operation
documented below. That role is deliberately mutation-capable for the later
CloudFormation workflow, but this operation permits only exact foundation
read-back, including `iam:GetSAMLProvider`, and writes a receipt stating that
neither CloudFormation nor IAM was mutated. Preserve the root sign-in, MFA,
approval, created resource inventory, federation test, sign-out, assignment
activation, observation receipt, and CloudTrail event evidence. Any mismatch
requires incident review; it is not repaired by widening a role. Root is
forbidden for every subsequent step.

The governed access workflow is the next repository-owned operation that needs the real
management account. Preparing its change set is a CloudFormation control-plane mutation;
executing it is the first IAM mutation. Neither is run by local gates or
qualification. Keep the provisioner assignment activated only for the governed
observation, prepare, and execute window, renewing its short-lived federated
session if necessary; then end it before retirement. Never use the root user
after the greenfield ceremony or create an IAM user/access key.
MFA is enforced and evidenced
at the upstream IdP; `aws:MultiFactorAuthPresent` is not a
reliable role-trust condition for federated sessions. The preview, apply,
provisioner, and fixed `ManagementSeedRetirement` source roles in the bundle
must already exist, use one-hour SAML sessions, and contain only their
corresponding rendered capped source policy. The target roles and immutable
managed boundaries must also match the rendered `precreatedFoundation`
exactly. The active provisioner has exactly
one `ManagementSeedAccessProvisioner` inline policy, the three exact
`DeusState=active` tags, no attached policy, and no permissions boundary. It is
not an administrator role: it cannot create roles or managed policies and can
install only the two named inline policies into the two already bounded target
roles through the exact reviewed change set.

Obtain the provisioner session through the `DeusBootstrap` SAML provider and
upstream IdP, then confirm `aws sts get-caller-identity` returns the exact
management account and assumed-role form of
`managementProvisionerPrincipalArn`. Do not
invoke CloudFormation directly. The governed provisioner binds the signed
candidate, exact provisioner caller, stack `deus-management-seed-access`,
bundle region and digest, and byte-exact RolePolicy-only template. Both
`ValidateTemplate` and `DescribeChangeSet` must report an empty capability set;
the installer stops if any capability is reported. Do not use a default CLI
profile during this step.

First observe and attest the complete empty foundation. This operation invokes
no CloudFormation API and performs no cloud mutation:

```sh
cd /usr/local/lib/deus-bootstrap/execution
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode access-provisioner --aws-fd 4 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <jit-provisioner> --format process) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    access-provisioner \
    --observe-foundation \
    --candidate artifacts/bootstrap-candidate.json \
    --confirm-bundle-digest <reviewed-bundle-sha256>
```

Review and retain
`artifacts/runtime-output/management-seed-access-foundation.observed.json`.
It binds the candidate, bundle, exact provisioner caller, and complete live
foundation-attestation digest, with both mutation flags false.

First prepare the change set. This writes CloudFormation control-plane state
but does not create IAM resources:

```sh
cd /usr/local/lib/deus-bootstrap/execution
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode access-provisioner --aws-fd 4 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <jit-provisioner> --format process) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    access-provisioner \
    --prepare \
    --candidate artifacts/bootstrap-candidate.json \
    --confirm-bundle-digest <reviewed-bundle-sha256>
```

The command accepts only a change set containing exactly two `Add` changes,
re-fetches the stored template, and writes a content-addressed prepared
receipt. Review that receipt and the change set, then separately authorize
execution:

```sh
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode access-provisioner --aws-fd 4 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <jit-provisioner> --format process) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    access-provisioner \
    --execute \
    --candidate artifacts/bootstrap-candidate.json \
    --confirm-bundle-digest <reviewed-bundle-sha256> \
    --confirm-execute INSTALL_EXACTLY_TWO_BOUNDED_IAM_ROLE_POLICIES
```

Execution re-checks the live change set and stored template, performs the IAM
mutation, waits for `CREATE_COMPLETE`, and verifies both target roles, the
preview/apply source roles, the independent retirement role, the active
provisioner, exact trust and inline-policy documents, boundary policies, sole
boundary default versions, tags, session durations, and absence of extra
attached policies.

Before the governed execute invocation, verify the prepared receipt, bundle
digest, nested template digest, both policy resources, and both exact trust
conditions. Authorize execution only after the receipt contains exactly:

- `PreviewRolePolicy` and `ApplyRolePolicy`, both
  `AWS::IAM::RolePolicy` `Add` changes targeting the precreated roles; and
- no replacement, deletion, wildcard principal, IAM user, access key, or
  resource outside those two policy resources.

The separately audited initial access-foundation setup must pre-create the exact
`DeusManagementSeedProvisionerRetiredBoundary` under `/deus/bootstrap/` with
one `Deny *` statement and no other version. Immediately after the two target
policies are verified, end the provisioner session and obtain a separate
session for the fixed `ManagementSeedRetirement` source role. That role can
read only the bounded access inventory and can mutate only the provisioner: it
attaches the exact deny-all boundary, deletes the sole exact inline grant, and
sets the exact retired tags in that order. It cannot add a policy, remove a
boundary, update trust, or mutate another role.

Run the governed retirement mode against the executed access receipt:

```sh
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode access-provisioner --aws-fd 4 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <jit-retirement> --format process) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    access-provisioner \
    --retire \
    --candidate artifacts/bootstrap-candidate.json \
    --receipt artifacts/runtime-output/management-seed-access-change-set.executed.json \
    --confirm-bundle-digest <reviewed-bundle-sha256> \
    --confirm-retire RETIRE_EXACT_MANAGEMENT_SEED_PROVISIONER
```

The runner attests one of four exact monotonic states (`active`, `bounded`,
`stripped`, or `retired`), performs only the next operation, retries the
eventually consistent read-back, resumes after interruption without undoing a
completed restriction, attests the complete retired state, and writes
a candidate-, bundle-, caller-, executed-receipt-, operation-order-, and
postcondition-bound retirement receipt. Then deactivate the provisioner at the
upstream IdP and record that external retirement. Seed
preview/apply live-attests the exact role ARN/path/trust/session duration,
three tags, zero policies, boundary metadata/sole version/document, and sole
boundary use. The explicit deny makes a stale upstream assignment inert, while
IdP deactivation remains separately governed external evidence. Standing
provisioner authorization is forbidden. Stack deletion does not revoke the
retained inline policies; revocation is an explicit incident/change operation
that removes the inline policies before independently retiring trust,
boundaries, and roles through a separately approved procedure.

The template is for a fresh policy installation into the exact precreated
foundation. If either target role already has any inline policy, or any role,
boundary, trust, tag, path, session duration, or boundary version differs,
stop and audit it instead of weakening the attestation or overwriting state.

AWS recommends federation and temporary credentials for human access, while a
permissions boundary limits a role's maximum permissions and does not grant
permissions by itself. This is why each generated role has both an inline
allow/deny policy and the matching boundary. The account-principal plus exact
`aws:PrincipalArn` condition also supports federated role
sessions without trusting every identity in the account. See the AWS guidance
for [IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html),
[permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html),
and [principal role-session behavior](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html).

The first management candidate must keep `seedWave: organization-only`. Its
saved plan may contain exactly the protected `aws.organizations.Organization`
resource. The preview manifest binds the verified absence of an Organization;
the apply rechecks that precondition and then independently proves the exact
Organization, root, management-only account inventory, enabled policy types,
default FullAWSAccess attachment, and absence of OUs, customer policies,
an Organizations resource policy, trusted service access, delegated
administrators, account work, and open
invitations. After that reviewed plan is applied, `seedWave: full` may be used
only for a completely new clean qualification, review, signature, and
read-only preview. Full apply is machine-blocked until a separately qualified
member-access installation can immediately replace and retire every
`DeusOrganizationBootstrap` role created by account vending. The full-wave gate queries
the effective Organizations quota through Service Quotas in `us-east-1`,
requires capacity for exactly nine accounts, rejects open invitations and
concurrent account creation, and rejects any existing member outside the
reviewed name/email set before Pulumi can run. Its candidate-, management
account-, and configuration-bound observation is frozen into the saved-plan
manifest and repeated immediately before and after Pulumi, including failure
paths.

## Read-only management-seed preview

Use an AWS SSO/OIDC/STS profile only as the source of one temporary
credential-process document. Never `eval` it and never export raw AWS or Pulumi
secrets. The static launcher can merge that document with a Pulumi token from
an independently approved secret reader, but it writes the result only to an
anonymous pipe. The credentialed launcher reads that pipe after disabling its
own dumpability, validates an `ASIA...` STS key and bounded expiry, starts an
authenticated loopback broker, and gives Node only the broker URI and a random
authorization capability.

On a fresh preview host/identity:

First use a SAML source profile whose role ARN equals
`managementPreviewTrustedPrincipalArn`, and a chained role profile whose
`role_arn` equals `managementPreviewRoleArn`. The AWS source must emit
`aws configure export-credentials --profile <chained-preview> --format process`.
`approved-pulumi-token-reader` below is a placeholder for the operator's
non-shell secret-manager command; it must emit only the short-lived Pulumi
token. Bash process substitution creates the two input pipes, the left native
process emits one combined anonymous pipe, and the root-managed transient
system service passes that same descriptor to the locked runtime as standard
input:

```sh
cd /usr/local/lib/deus-bootstrap/execution
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode bootstrap --aws-fd 4 --pulumi-token-fd 5 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <chained-preview> --format process) \
  5< <(approved-pulumi-token-reader) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    bootstrap \
    --environment dev --phases seed --preview \
    --candidate artifacts/bootstrap-candidate.json \
    --confirm-management-account-id 111122223333
```

The systemd no-exec namespace and inner Landlock policy are preventive
authorization, not self-reported evidence. During the
dedicated Linux acceptance run, observe one preview with an independently
administered, root-owned audit/eBPF/ptrace facility whose output directory is
not writable by `deus-runtime`; never treat a trace in `runtime-output` or a
same-UID generated report as trusted. The observer must confirm the launcher,
Node, Pulumi, language host, policy analyzer, AWS CLI, and exact AWS provider,
and zero denied or unexpected execution attempts. This diagnostic validates
the deployment's kernel behavior but does not replace Landlock or authorize
apply by itself. Review the complete diff, saved plan, observer output, and
manifest digest. The runtime-owned plan directory is deliberately not readable
by the operator. After preview, use the digest printed by the preview to create
one root-frozen, content-addressed export:

```sh
sudo --non-interactive /usr/local/bin/deus-aws-bootstrap export-plan-review \
  --manifest-digest <printed-sha256>
find "/var/lib/deus-bootstrap-plan-reviews/<printed-sha256>" \
  -maxdepth 1 -type f -print
```

The export reopens each runtime-owned file without following a symlink,
requires exact runtime UID/GID and mode `0600`, verifies every plan hash against
the strict manifest, and publishes root-owned mode `0440` bytes to the
`deus-bootstrap-operators` group. It never grants the operator a shell or
general root read. The root runtime service refuses `--apply` unless this exact
content-addressed export exists, has no extra files, and its manifest and every
plan hash revalidate. This enforces the freeze transition; human review remains
an operator responsibility. Review that frozen manifest/plans, the complete
console diff, observer output, and digest. On a separate fresh apply session
using the distinct apply role:

```sh
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode bootstrap --aws-fd 4 --pulumi-token-fd 5 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <chained-apply> --format process) \
  5< <(approved-pulumi-token-reader) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    bootstrap \
    --environment dev --phases seed --apply \
    --candidate artifacts/bootstrap-candidate.json \
    --confirm-management-account-id 111122223333 \
    --confirm-plan-manifest-digest <reviewed-sha256>
```

Pulumi reads the reviewed plan from a private unlinked snapshot descriptor, so
path replacement and in-place mutation of the original plan cannot change the
bytes passed to apply.

If Pulumi reports success but the bounded post-apply observer times out while
AWS is still converging, do not rerun the update. Freeze the same reviewed plan
export and use the distinct preview role with the read-only recovery mode:

```sh
/usr/local/bin/deus-aws-bootstrap credential-envelope \
  --mode organization-recovery --aws-fd 4 \
  4< <(/usr/local/lib/deus-bootstrap/bin/aws configure export-credentials \
    --profile <chained-preview> --format process) |
  sudo --non-interactive /usr/local/bin/deus-aws-bootstrap runtime-service \
    organization-recovery \
    --environment dev --phases seed \
    --candidate artifacts/bootstrap-candidate.json \
    --confirm-management-account-id 111122223333 \
    --confirm-plan-manifest-digest <reviewed-sha256>
```

The AWS-only recovery path accepts no Pulumi secret or capability, never
invokes Pulumi, and performs no AWS mutation. It
revalidates the signed candidate, frozen manifest and exact management plan,
reviewed standalone attestation, caller/access state, source revision, and
exact converged Organization baseline, then writes a strict digest-bound
receipt under `artifacts/runtime-output`. Mixed, foreign, full-wave, stale, or
unbound state fails closed.

The first preview is the first read-only Organizations operation after the
one-time access-foundation boundary. No AWS call is made by rendering, build, tests,
qualification, signing finalization, or release packaging. Current AWS
Organizations action/resource/condition support is documented in the
[AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsorganizations.html).

Before backend inspection and immediately before and after every Pulumi
preview/apply boundary, the credentialed bootstrap repeats the full live IAM
attestation. A same-name role recreated with widened trust, a changed or
missing boundary, an extra policy, a different default version, or a modified
source grant blocks Pulumi even when its STS ARN still looks correct. Proxy,
endpoint, profile, preload, and custom-CA indirection are rejected before the
broker can disclose credentials. Raw AWS and Pulumi secrets never enter Node's
initial environment; downstream AWS SDKs obtain expiring credentials from the
authenticated loopback endpoint, and only Pulumi children receive the Pulumi
token fetched in-process after candidate verification.
