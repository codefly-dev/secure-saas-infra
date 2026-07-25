# Pulumi Cloud State Recovery

This is the recovery procedure for the only admitted Pulumi backend and stack:

| Field                    | Selected value                                             |
| ------------------------ | ---------------------------------------------------------- |
| Backend                  | Pulumi Cloud (`https://api.pulumi.com`)                    |
| Organization             | `toussaint-antoine-gmail-com`                              |
| Project                  | `secure-saas-infra`                                        |
| Stack                    | `management`                                               |
| Fully qualified stack    | `toussaint-antoine-gmail-com/secure-saas-infra/management` |
| Secrets provider         | Pulumi Cloud service encryption                            |
| Recovery point objective | One hour and after every successful update                 |

The machine-readable authority is
[`security/pulumi-cloud-backend.json`](../security/pulumi-cloud-backend.json).
Only the empty `management` backend stack has been initialized. Initialization
does not authorize a Pulumi preview, update, refresh, import, destroy, or any
AWS provider action. No later-wave stack may be initialized.

## Human account recovery

The selected account is federated through Google and has a Pulumi passkey
registered in the owner's password manager. Pulumi-hosted TOTP MFA and its
recovery key are documented for email/password accounts; they are not the
recovery mechanism for this Google-backed account. Pulumi's `hasMFA` user
attribute can therefore remain `false` and does not describe the Google
account's MFA posture. See the
[Pulumi account authentication documentation](https://www.pulumi.com/docs/pulumi-cloud/accounts/).

Before the first AWS preview, the owner must:

1. Protect the Google identity used to log in to Pulumi with Google 2-Step
   Verification and at least two independent authentication methods.
2. Store Google backup codes and confirm its recovery email or phone through a
   route that does not depend on Pulumi, GitHub, AWS, or the primary device.
3. Retain the Pulumi passkey in the protected password manager and retain that
   password manager's own recovery material independently of the primary
   device.
4. Record a recovery contact and perform a fresh private-browser login drill
   through both the Pulumi passkey and Google without disabling either
   authentication path.

Never commit a Pulumi access token, passkey, identity-provider recovery
material, stack export, or stack configuration. A CLI personal token is not a
human account recovery method. The local interactive login is sufficient
during bootstrap. Do not create a CI token until a reviewed deployment
workflow exists. On the free Pulumi tier, any later automation token must be a
short-lived personal token; moving to an organization-owned automation
identity is a paid-control decision.

## Normal state export

The disaster-recovery RPO is one hour. Run an export after every successful
Pulumi update and at least hourly while changes are active:

```sh
mkdir -m 700 /path/on/encrypted-independent-storage/pulumi-state
node scripts/backup-pulumi-cloud-state.mjs \
  --output-dir /path/on/encrypted-independent-storage/pulumi-state
```

The destination must be an existing absolute path outside this repository.
It must be encrypted, access-controlled, and backed up independently of
Pulumi, GitHub, and the AWS organization being managed. Keep at least two
copies in separate failure domains.

The command verifies the Pulumi identity and exact Cloud stack before reading
state. It exports the service-encrypted deployment, never requests plaintext
secrets, writes the state and checksum with mode `0600`, and refuses to
overwrite an existing file. Verify a copy with:

```sh
cd /path/on/encrypted-independent-storage/pulumi-state
shasum -a 256 -c pulumi-*.json.sha256
```

Treat even a service-encrypted export as confidential infrastructure metadata.
The checksum proves file integrity, not authenticity; storage access controls
and retained Pulumi update evidence provide provenance.

## Recovery decision tree

### Account login is unavailable

Recover the Pulumi login through the registered Pulumi passkey or the protected
Google identity and its stored recovery methods. Do not treat an existing CLI
personal token as proof that human account recovery works. Re-run `pulumi
login`, then require:

```sh
pulumi whoami --json --verbose
pulumi stack ls --json
```

Stop unless the organization, project, stack URL, and backend match the
machine-readable decision. A normal service-encrypted export is not a
standalone substitute for recovering access to the Pulumi Cloud secrets
provider.

### The stack was accidentally deleted

The Individual Edition does not provide Pulumi Cloud's self-service
[deleted-stack restoration](https://www.pulumi.com/docs/deployments/projects-and-stacks/#restoring-a-stack).
That console feature is limited to higher paid editions, so it is not part of
this free recovery design.

Stop all writers and do not run an AWS refresh. Verify the last external
export, its checksum, stack identity, resource inventory, and retained update
evidence. With explicit recovery approval, initialize the exact same
organization/project/stack name using the Pulumi Cloud secrets provider and
import only that reviewed export. Do not use `--force`. If the normal import
fails, preserve the error and contact Pulumi support; do not improvise a
refresh or provider update.

After import, verify the exact identity and stack URL, export the recovered
state, compare it with the reviewed recovery input, and run only the
repository's governed read-only checks.

### The live state is corrupt but the stack exists

1. Stop all writers and export the current state as quarantined evidence.
2. Select the last known-good Cloud update or verified external export.
3. Independently review the resource inventory, stack identity, checksum, and
   incident scope.
4. With explicit recovery approval, restore the reviewed file:

   ```sh
   pulumi stack import \
     --stack toussaint-antoine-gmail-com/secure-saas-infra/management \
     --file /reviewed/recovery/pulumi-management-state.json
   ```

5. Export again and compare the restored state. Do not use `--force`. Do not
   run `pulumi refresh`, `pulumi preview`, or `pulumi up` as a substitute for
   state review.

Import mutates Pulumi state. It is never part of a backup test and requires
separate human approval tied to an incident or migration.

### Pulumi Cloud exit or backend migration

Do not copy backend objects directly. While the current Pulumi identity and
secrets provider are healthy, export the stack and import it through the
Pulumi CLI into a separately reviewed destination backend. A cross-backend
escrow that exposes plaintext secret values is prohibited by the current
decision. If portability of encrypted secrets becomes a requirement, first
approve and qualify a different secrets provider and a confidential migration
ceremony.

Upgrading the Pulumi subscription does not by itself require a state move.
Organization-owned tokens, teams, RBAC, and other paid controls may be added
later without changing this stack identity.

## Drill and evidence

Before the first AWS preview and quarterly thereafter:

1. Run a normal export to the independent destination.
2. Verify file permissions and the SHA-256 sidecar.
3. Confirm a second authorized recovery operator can retrieve the copy and
   identify the exact stack without viewing plaintext secrets.
4. Confirm the Pulumi passkey, Google 2-Step Verification recovery material,
   and password-manager recovery material are available without exposing them.
5. Record the export timestamp, checksum, operator, storage copy locations,
   and outcome outside the repository.

Do not import the production state merely to test a backup. A destructive or
state-mutating drill requires a separately approved isolated recovery stack
and must never contact AWS with the management credentials.
