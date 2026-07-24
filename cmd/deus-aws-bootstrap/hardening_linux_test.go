//go:build linux

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestPlanReviewManifestIsStrictAndContentAddressed(t *testing.T) {
	planDigest := strings.Repeat("b", 64)
	valid := fmt.Sprintf(`{"apiVersion":"security.deus.dev/pulumi-plan-manifest/v1alpha1","kind":"PulumiPlanManifest","generatedAt":"2026-07-20T12:00:00Z","sourceRevision":%q,"managementAccountId":"111122223333","pulumiOrganization":"deus","pulumiProject":"secure-saas-infra","bootstrapCandidateDigest":%q,"plans":[{"stack":"management","planFile":"management.plan.json","sha256":%q}]}`,
		strings.Repeat("a", 40), strings.Repeat("c", 64), planDigest)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(valid)))
	if _, err := parsePlanReviewManifest([]byte(valid), digest); err != nil {
		t.Fatalf("valid plan review manifest was rejected: %v", err)
	}
	unknown := strings.Replace(valid, `"kind":`, `"unknown":true,"kind":`, 1)
	for name, hostile := range map[string]struct {
		contents string
		digest   string
	}{
		"wrong digest":  {valid, digest[:63] + "0"},
		"unknown field": {unknown, fmt.Sprintf("%x", sha256.Sum256([]byte(unknown)))},
	} {
		if _, err := parsePlanReviewManifest([]byte(hostile.contents), hostile.digest); err == nil {
			t.Fatalf("%s plan review manifest was accepted", name)
		}
	}
}

func TestFrozenPlanReviewIsMandatoryAndFullyRevalidated(t *testing.T) {
	plan := []byte("exact saved plan\n")
	planDigest := fmt.Sprintf("%x", sha256.Sum256(plan))
	manifest := []byte(fmt.Sprintf(`{"apiVersion":"security.deus.dev/pulumi-plan-manifest/v1alpha1","kind":"PulumiPlanManifest","generatedAt":"2026-07-20T12:00:00Z","sourceRevision":%q,"managementAccountId":"111122223333","pulumiOrganization":"deus","pulumiProject":"secure-saas-infra","bootstrapCandidateDigest":%q,"plans":[{"stack":"management","planFile":"management.plan.json","sha256":%q}]}`,
		strings.Repeat("a", 40), strings.Repeat("c", 64), planDigest))
	digest := fmt.Sprintf("%x", sha256.Sum256(manifest))
	directory := filepath.Join(t.TempDir(), digest)
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(directory, 0o700); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore frozen plan review directory permissions: %v", err)
		}
	})
	for name, contents := range map[string][]byte{
		"manifest.json":        manifest,
		"management.plan.json": plan,
	} {
		value := filepath.Join(directory, name)
		if err := os.WriteFile(value, contents, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(value, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(directory, 0o550); err != nil {
		t.Fatal(err)
	}
	if err := validateFrozenPlanReview(directory, digest, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("exact frozen plan review was rejected: %v", err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("bypass"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o550); err != nil {
		t.Fatal(err)
	}
	if err := validateFrozenPlanReview(directory, digest, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("frozen plan review with an unexpected file was accepted")
	}
}

func TestApplyRequiresExactFrozenPlanDigestArgument(t *testing.T) {
	digest := strings.Repeat("a", 64)
	value, apply, err := applyPlanReviewRequirement([]string{"--apply", "--confirm-plan-manifest-digest", digest})
	if err != nil || !apply || value != digest {
		t.Fatalf("exact apply confirmation was rejected: %q %t %v", value, apply, err)
	}
	value, recovery, err := applyPlanReviewRequirement([]string{"--recover-organization-state", "--confirm-plan-manifest-digest", digest})
	if err != nil || !recovery || value != digest {
		t.Fatalf("exact recovery confirmation was rejected: %q %t %v", value, recovery, err)
	}
	for name, args := range map[string][]string{
		"missing digest":          {"--apply"},
		"duplicate apply":         {"--apply", "--apply", "--confirm-plan-manifest-digest", digest},
		"boolean injection":       {"--apply=true", "--confirm-plan-manifest-digest", digest},
		"duplicate digest":        {"--apply", "--confirm-plan-manifest-digest", digest, "--confirm-plan-manifest-digest=" + digest},
		"recovery missing digest": {"--recover-organization-state"},
		"duplicate recovery":      {"--recover-organization-state", "--recover-organization-state", "--confirm-plan-manifest-digest", digest},
		"recovery injection":      {"--recover-organization-state=true", "--confirm-plan-manifest-digest", digest},
		"apply plus recovery":     {"--apply", "--recover-organization-state", "--confirm-plan-manifest-digest", digest},
	} {
		if _, _, err := applyPlanReviewRequirement(args); err == nil {
			t.Fatalf("%s apply arguments were accepted", name)
		}
	}
}

func TestRuntimeProvenanceParserRejectsUnknownOrTrailingContent(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := fmt.Sprintf(`{
  "apiVersion":"security.deus.dev/bootstrap-runtime-provenance/v1",
  "platform":"linux",
  "architecture":%q,
  "artifacts":{
    "go":{"file":"go.tar.gz","sha256":%q,"verification":"authenticated-host-kit-pinned-sha256"},
    "node":{"file":"node.tar.xz","sha256":%q,"verification":"authenticated-host-kit-pinned-sha256"},
    "pulumi":{"file":"pulumi.tar.gz","sha256":%q,"verification":"authenticated-host-kit-pinned-sha256"},
    "awsCli":{"file":"aws.zip","sha256":%q,"verification":"aws-cli-team-pgp","signingKeyFingerprint":"FB5DB77FD5C118B80511ADA8A6310ACC4672475C"}
  },
  "installed":{"goSha256":%q,"nodeSha256":%q,"pulumiTreeDigest":%q,"awsCliTreeDigest":%q},
  "systemRuntime":{"apiVersion":"security.deus.dev/system-runtime-closure/v1","architecture":%q,"loaders":[{"path":"/lib/loader.so","sha256":%q}],"libraries":[]}
}`, runtime.GOARCH, digest, digest, digest, digest, digest, digest, digest, digest, runtime.GOARCH, digest)
	if _, err := parseBootstrapRuntimeProvenance([]byte(valid)); err != nil {
		t.Fatalf("strict runtime provenance was rejected: %v", err)
	}
	for name, hostile := range map[string]string{
		"top-level unknown": strings.Replace(valid, `"platform":"linux",`, `"platform":"linux","unknown":true,`, 1),
		"nested unknown":    strings.Replace(valid, `"go":{"file":`, `"go":{"unknown":true,"file":`, 1),
		"trailing document": valid + `{}`,
	} {
		if _, err := parseBootstrapRuntimeProvenance([]byte(hostile)); err == nil {
			t.Fatalf("%s runtime provenance was accepted", name)
		}
	}
}

func TestCredentialReadablePolicyExcludesQualificationTooling(t *testing.T) {
	files, directories := credentialReadablePathPolicy("/tmp/isolated-home")
	joined := strings.Join(append(append([]string{}, files...), directories...), "\n")
	for _, forbidden := range []string{
		installRoot + "\n",
		installRoot + "/qualification",
		installRoot + "/qualification-bin",
		installRoot + "/toolchains/go",
	} {
		if strings.Contains(joined+"\n", forbidden) {
			t.Fatalf("credential-readable policy exposes qualification path %s", forbidden)
		}
	}
	for _, required := range []string{
		stage1Path,
		trustPath,
		runtimeIdentityPath,
		runtimeProvenancePath,
		executionRoot,
		installRoot + "/toolchains/aws-cli/v2/current/dist",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("credential-readable policy lacks %s", required)
		}
	}
}

func TestAnonymousPipeProofRejectsNamedFIFO(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := requireAnonymousPipe(reader, "test input"); err != nil {
		t.Fatalf("anonymous pipe was rejected: %v", err)
	}

	fifoPath := filepath.Join(t.TempDir(), "credential.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo, err := os.OpenFile(fifoPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fifo.Close()
	if err := requireAnonymousPipe(fifo, "test input"); err == nil || !strings.Contains(err.Error(), "anonymous pipe") {
		t.Fatalf("named FIFO was accepted: %v", err)
	}
}

func TestSealedSigningBundleCannotBeMutated(t *testing.T) {
	file, err := createSealedBundle([]byte("trusted bundle"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil || string(contents) != "trusted bundle" {
		t.Fatalf("sealed bundle content changed: %q, %v", contents, err)
	}
	if _, err := file.WriteAt([]byte("attacker"), 0); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("sealed bundle write was not denied with EPERM: %v", err)
	}
	if err := file.Truncate(1); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("sealed bundle truncate was not denied with EPERM: %v", err)
	}
}

func TestSealedSigningBundleIsAuthenticatedAfterServiceHandoff(t *testing.T) {
	file, err := createSealedBundle([]byte("confidential signing review"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	contents, err := readSealedSigningBundle(file)
	if err != nil || string(contents) != "confidential signing review" {
		t.Fatalf("sealed service bundle was rejected: %q %v", contents, err)
	}
	temporary, err := os.CreateTemp(t.TempDir(), "ordinary-bundle-")
	if err != nil {
		t.Fatal(err)
	}
	defer temporary.Close()
	if _, err := temporary.WriteString("unsealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := temporary.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readSealedSigningBundle(temporary); err == nil {
		t.Fatal("ordinary file was accepted as a root-sealed service bundle")
	}
}

func TestLockedRuntimeAccountRejectsSupplementaryAuthority(t *testing.T) {
	passwd := []byte("deus-runtime:x:994:994::/nonexistent:/usr/sbin/nologin\n")
	if err := validateLockedRuntimeAccount(passwd, 994, 994, nil); err != nil {
		t.Fatalf("minimal locked account was rejected: %v", err)
	}
	if err := validateLockedRuntimeAccount(passwd, 994, 994, []int{994}); err != nil {
		t.Fatalf("primary group duplicate was rejected: %v", err)
	}
	if err := validateLockedRuntimeAccount(passwd, 994, 994, []int{994, 999}); err == nil || !strings.Contains(err.Error(), "supplementary group") {
		t.Fatalf("dangerous supplementary group was accepted: %v", err)
	}
	alias := append(passwd, []byte("attacker:x:994:994::/home/attacker:/bin/bash\n")...)
	if err := validateLockedRuntimeAccount(alias, 994, 994, nil); err == nil || !strings.Contains(err.Error(), "exclusively") {
		t.Fatalf("login-capable UID alias was accepted: %v", err)
	}
}

func TestLockedRuntimeShadowAccountIsUniqueAndPasswordLocked(t *testing.T) {
	for _, password := range []string{"!", "!*", "*"} {
		shadow := []byte("root:*:1:0:99999:7:::\ndeus-runtime:" + password + ":1:0:99999:7:::\n")
		if err := validateLockedShadowAccount(shadow); err != nil {
			t.Fatalf("locked password marker %q was rejected: %v", password, err)
		}
	}
	for name, shadow := range map[string]string{
		"missing":   "root:*:1:0:99999:7:::\n",
		"unlocked":  "deus-runtime:$6$hash:1:0:99999:7:::\n",
		"duplicate": "deus-runtime:!:1:0:99999:7:::\ndeus-runtime:*:1:0:99999:7:::\n",
	} {
		if err := validateLockedShadowAccount([]byte(shadow)); err == nil {
			t.Fatalf("%s shadow account was accepted", name)
		}
	}
}

func TestDedicatedSignerIdentityRejectsLoginAndSupplementaryAuthority(t *testing.T) {
	passwd := []byte("deus-signer-runtime:x:993:993::/nonexistent:/usr/sbin/nologin\n")
	shadow := []byte("deus-signer-runtime:!:1:0:99999:7:::\n")
	group := []byte("deus-signer-runtime:x:993:\n")
	if err := validateDedicatedSignerIdentity(passwd, shadow, group, 993, 993); err != nil {
		t.Fatalf("dedicated locked signer was rejected: %v", err)
	}
	for name, hostile := range map[string]struct {
		passwd []byte
		shadow []byte
		group  []byte
	}{
		"login shell":   {[]byte("deus-signer-runtime:x:993:993::/home/signer:/bin/bash\n"), shadow, group},
		"unlocked":      {passwd, []byte("deus-signer-runtime:$6$hash:1:0:99999:7:::\n"), group},
		"supplementary": {passwd, shadow, []byte("deus-signer-runtime:x:993:\nwheel:x:10:deus-signer-runtime\n")},
		"uid alias":     {append(passwd, []byte("attacker:x:993:993::/home/attacker:/bin/bash\n")...), shadow, group},
	} {
		if err := validateDedicatedSignerIdentity(hostile.passwd, hostile.shadow, hostile.group, 993, 993); err == nil {
			t.Fatalf("%s signer identity was accepted", name)
		}
	}
}

func TestPreparedSignerTreeRejectsIgnoredModuleShadowAndSymlinkAncestor(t *testing.T) {
	fixture := func(t *testing.T) (string, signerSourceManifest) {
		t.Helper()
		root := t.TempDir()
		contents := []byte("trusted verifier\n")
		if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "scripts", "verifier.mjs"), contents, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, directory := range []string{
			".git/objects",
			"artifacts/bootstrap-pulumi-home/plugins/resource-aws-v7.27.0",
			"dist-management-seed",
			"dist-management-seed-policy",
			"dist-management-seed-support",
			"node_modules/.bin",
			"node_modules/ajv",
		} {
			if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "artifacts", "deus-aws-bootstrap"), []byte("launcher"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "node_modules", "ajv", "cli.js"), []byte("trusted dependency"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../ajv/cli.js", filepath.Join(root, "node_modules", ".bin", "ajv")); err != nil {
			t.Fatal(err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(contents))
		manifestJSON := fmt.Sprintf(`{"apiVersion":"security.deus.dev/bootstrap-host-source-manifest/v1","releaseTag":"v1.0.0","sourceRevision":%q,"files":[{"path":"scripts/verifier.mjs","executable":false,"sha256":%q}],"manifestDigest":%q}`,
			strings.Repeat("a", 40), digest, strings.Repeat("b", 64))
		manifest, err := parseSignerSourceManifest([]byte(manifestJSON))
		if err != nil {
			t.Fatal(err)
		}
		return root, manifest
	}

	t.Run("exact reconstructed closure", func(t *testing.T) {
		root, manifest := fixture(t)
		if err := validatePreparedSignerReviewTree(root, manifest); err != nil {
			t.Fatalf("exact prepared tree was rejected: %v", err)
		}
		defer func() {
			_ = filepath.WalkDir(root, func(value string, entry os.DirEntry, err error) error {
				if err == nil && entry.Type()&os.ModeSymlink == 0 {
					if entry.IsDir() {
						_ = os.Chmod(value, 0o700)
					} else {
						_ = os.Chmod(value, 0o600)
					}
				}
				return nil
			})
		}()
		if err := freezeSignerReviewTreeAs(root, os.Getuid(), os.Getgid()); err != nil {
			t.Fatalf("prepared tree with npm bin symlink could not be frozen: %v", err)
		}
		if info, err := os.Lstat(filepath.Join(root, "node_modules", ".bin", "ajv")); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("contained npm bin symlink was not preserved: %v", err)
		}
	})
	t.Run("fresh snapshot breaks old writable descriptors", func(t *testing.T) {
		root, manifest := fixture(t)
		dependency := filepath.Join(root, "node_modules", "ajv", "cli.js")
		old, err := os.OpenFile(dependency, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer old.Close()
		before, err := old.Stat()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = filepath.WalkDir(root, func(value string, entry os.DirEntry, err error) error {
				if err == nil && entry.Type()&os.ModeSymlink == 0 {
					_ = os.Chmod(value, 0o700)
				}
				return nil
			})
		}()
		if err := replaceSignerReviewTreeWithSnapshotAs(root, manifest, os.Getuid(), os.Getgid(), os.Geteuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		if _, err := old.WriteAt([]byte("attacker mutation"), 0); err != nil {
			t.Fatal(err)
		}
		sealed, err := os.ReadFile(dependency)
		if err != nil {
			t.Fatal(err)
		}
		if string(sealed) != "trusted dependency" {
			t.Fatalf("old descriptor changed fresh signer snapshot: %q", sealed)
		}
		after, err := os.Stat(dependency)
		if err != nil {
			t.Fatal(err)
		}
		beforeStat, beforeOK := infoSyscallStat(before)
		afterStat, afterOK := infoSyscallStat(after)
		if !beforeOK || !afterOK || beforeStat.Ino == afterStat.Ino {
			t.Fatal("signer snapshot did not publish fresh file inodes")
		}
	})
	t.Run("nested module shadow", func(t *testing.T) {
		root, manifest := fixture(t)
		shadow := filepath.Join(root, "scripts", "node_modules", "ajv")
		if err := os.MkdirAll(shadow, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shadow, "index.js"), []byte("steal fd 3"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validatePreparedSignerReviewTree(root, manifest); err == nil || !strings.Contains(err.Error(), "unexpected ignored path") {
			t.Fatalf("nested module shadow was accepted: %v", err)
		}
	})
	t.Run("symlinked tracked ancestor", func(t *testing.T) {
		root, manifest := fixture(t)
		external := t.TempDir()
		if err := os.WriteFile(filepath.Join(external, "verifier.mjs"), []byte("trusted verifier\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(root, "scripts")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, filepath.Join(root, "scripts")); err != nil {
			t.Fatal(err)
		}
		if err := validatePreparedSignerReviewTree(root, manifest); err == nil {
			t.Fatal("symlinked tracked ancestor was accepted")
		}
	})
}

func TestRuntimeSudoersIsDigestBoundAndDisablesPTYOnlyForAlias(t *testing.T) {
	digest := strings.Repeat("a", 64)
	policy, err := renderRuntimeSudoers(digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Cmnd_Alias DEUS_BOOTSTRAP_RUNTIME = sha256:" + digest,
		launcherPath + " ^runtime-service (bootstrap|access-provisioner|organization-recovery)",
		launcherPath + " ^export-plan-review --manifest-digest [a-f0-9]{64}$",
		"Defaults!DEUS_BOOTSTRAP_RUNTIME !use_pty",
		"%deus-bootstrap-operators ALL=(root) NOPASSWD: NOSETENV: DEUS_BOOTSTRAP_RUNTIME",
	} {
		if !strings.Contains(policy, required) {
			t.Fatalf("sudoers policy lacks %q: %s", required, policy)
		}
	}
	if _, err := renderRuntimeSudoers("not-a-digest"); err == nil {
		t.Fatal("invalid launcher digest was accepted")
	}
}

func TestSignerSudoersAllowsOnlyTheFixedTwoPhaseService(t *testing.T) {
	digest := strings.Repeat("d", 64)
	policy, err := renderSignerSudoers(digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"sha256:" + digest,
		launcherPath + " ^signing-review-service --signer-uid [1-9][0-9]* --signer-gid [1-9][0-9]*$",
		"%deus-bootstrap-signers ALL=(root) NOPASSWD: NOSETENV: DEUS_BOOTSTRAP_SIGNER",
	} {
		if !strings.Contains(policy, required) {
			t.Fatalf("signer sudoers policy lacks %q", required)
		}
	}
	if strings.Contains(policy, "signing-review ^") || strings.Contains(policy, " ALL$") {
		t.Fatal("signer sudoers bypasses the fixed two-phase service")
	}
}

func TestRuntimeServicePolicyKeepsProcSysVisibleForYamaCheck(t *testing.T) {
	text := strings.Join(runtimeServiceCommandArgs([]string{"/trusted/node"}, []string{"bootstrap"}), "\n")
	for _, required := range []string{
		"--property=ProtectProc=invisible",
		"--property=ProcSubset=all",
		"--property=NoExecPaths=/",
		"--property=RestrictNamespaces=yes",
		"--property=SystemCallFilter=~@mount memfd_create",
		"--property=RestrictAddressFamilies=AF_INET AF_INET6",
		"--property=InaccessiblePaths=-/run/dbus -/run/systemd/private -/run/user",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("runtime service policy is missing %s", required)
		}
	}
	if strings.Contains(text, "--property=ProcSubset=pid") {
		t.Fatal("ProcSubset=pid hides the Yama sysctl checked by the credential launcher")
	}
	if strings.Contains(text, "AF_UNIX") {
		t.Fatal("credential runtime unnecessarily admits Unix sockets")
	}
}

func TestRuntimeServiceOptionTerminatorProtectsForwardedArguments(t *testing.T) {
	forwarded := "--property=ProtectSystem=off"
	args := runtimeServiceCommandArgs([]string{"/trusted/node"}, []string{"bootstrap", forwarded})
	terminator, launcher, hostile := -1, -1, -1
	for index, value := range args {
		switch value {
		case "--":
			terminator = index
		case launcherPath:
			launcher = index
		case forwarded:
			hostile = index
		}
	}
	if terminator < 0 || launcher != terminator+1 || hostile <= launcher {
		t.Fatalf("unsafe systemd-run argument ordering: %v", args)
	}
}

func TestRuntimeServiceRequiresExactUnifiedCgroup(t *testing.T) {
	if !inRuntimeServiceCgroup([]byte("0::/system.slice/deus-bootstrap-runtime.service\n")) {
		t.Fatal("exact fixed runtime service cgroup was rejected")
	}
	for _, hostile := range []string{
		"0::/user.slice/deus-bootstrap-runtime.service\n",
		"0::/system.slice/deus-bootstrap-runtime.service/attacker\n",
		"2:cpu:/system.slice/deus-bootstrap-runtime.service\n",
		"0::/system.slice/prefix-deus-bootstrap-runtime.service\n",
	} {
		if inRuntimeServiceCgroup([]byte(hostile)) {
			t.Fatalf("non-exact runtime service cgroup was accepted: %q", hostile)
		}
	}
}

func TestSignerServicesSeparateOnlinePreparationFromPrivateReadOnlyReview(t *testing.T) {
	prepare := strings.Join(signerServiceCommandArgs("prepare", 1001, 1001), "\n")
	review := strings.Join(signerServiceCommandArgs("review", 1001, 1001), "\n")
	for _, required := range []string{
		"--unit=deus-bootstrap-signing-prepare",
		"--property=WorkingDirectory=" + executionRoot,
		"--property=KillMode=control-group",
		"--property=PrivateNetwork=no",
		"--property=RestrictAddressFamilies=AF_INET AF_INET6",
		"--property=InaccessiblePaths=-/run/dbus -/run/systemd/private -/run/user",
		"--property=ReadWritePaths=" + executionRoot,
		"signing-prepare",
	} {
		if !strings.Contains(prepare, required) {
			t.Fatalf("signer preparation service lacks %s", required)
		}
	}
	for _, required := range []string{
		"--unit=deus-bootstrap-signing-review",
		"--property=WorkingDirectory=" + executionRoot,
		"--property=KillMode=control-group",
		"--property=PrivateNetwork=yes",
		"--property=RestrictAddressFamilies=AF_UNIX",
		"--property=SystemCallFilter=~@mount @network-io",
		"--property=ReadOnlyPaths=" + executionRoot,
		"signing-review\n--bundle-fd\n0",
	} {
		if !strings.Contains(review, required) {
			t.Fatalf("signer review service lacks %s", required)
		}
	}
	if strings.Contains(review, "ReadWritePaths=") || strings.Contains(prepare, signingReviewBundle) {
		t.Fatal("signer service phases collapse writable preparation and confidential review")
	}
	if !inExactUnifiedCgroup([]byte("0::"+signingReviewCgroup+"\n"), signingReviewCgroup) ||
		inExactUnifiedCgroup([]byte("0::"+signingPrepareCgroup+"/child\n"), signingPrepareCgroup) {
		t.Fatal("signer service cgroup proof is not exact")
	}
}
