// deus-aws-bootstrap is the only supported credential-bearing entrypoint for
// the AWS management seed. It must be installed root-owned and non-writable at
// /usr/local/bin/deus-aws-bootstrap. The JavaScript verifier and qualified
// execution snapshot are separate root-owned trust domains under installRoot.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	expectedStage1SHA256 = "UNSET"
	expectedTrustSHA256  = "UNSET"
)

const (
	installRoot           = "/usr/local/lib/deus-bootstrap"
	executionRoot         = installRoot + "/execution"
	nodePath              = installRoot + "/bin/node"
	stage1Path            = installRoot + "/credentialed-bootstrap-stage1.mjs"
	trustPath             = installRoot + "/bootstrap-qualification-trust.json"
	runtimeIdentityPath   = installRoot + "/runtime-identity"
	runtimeProvenancePath = installRoot + "/runtime-provenance.json"
	signingStage0Path     = installRoot + "/bootstrap-signing-stage0.mjs"
	sourceManifestPath    = installRoot + "/management-seed-source-manifest.json"
	releaseIdentityPath   = installRoot + "/RELEASE"
	launcherPath          = "/usr/local/bin/deus-aws-bootstrap"
	pulumiHome            = executionRoot + "/artifacts/bootstrap-pulumi-home"
	sealMaximumEntries    = 300_000
	sealMaximumFileSize   = 2 * 1024 * 1024 * 1024
	sealMaximumTreeSize   = 8 * 1024 * 1024 * 1024
)

var allowedEnvironment = map[string]bool{
	"AWS_DEFAULT_REGION": true,
	"AWS_REGION":         true,
	"LANG":               true,
	"LC_ALL":             true,
	"TERM":               true,
}

func main() {
	err := disableProcessDumpability()
	if err == nil && len(os.Args) > 1 && os.Args[1] == "credential-envelope" {
		err = runCredentialEnvelope(os.Args[2:], os.Environ(), os.Stdout, time.Now().UTC())
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "runtime-elf-closure" {
		err = writeRuntimeELFClosure(os.Args[2:])
	} else if err == nil && len(os.Args) > 1 && (os.Args[1] == "prepare-execution" || os.Args[1] == "seal-execution") {
		if os.Args[1] == "prepare-execution" {
			err = prepareExecution(os.Args[2:], os.Environ())
		} else {
			err = sealExecution(os.Args[2:], os.Environ())
		}
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "signing-review" {
		err = runSigningReview(os.Args[2:], os.Environ(), os.Stdin, os.Stdout, os.Stderr)
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "signing-prepare" {
		err = runSigningPreparation(os.Args[2:], os.Environ(), os.Stdout, os.Stderr)
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "signing-review-service" {
		err = runSigningReviewService(os.Args[2:], os.Environ(), os.Stdout, os.Stderr)
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "runtime-service" {
		err = runRuntimeService(os.Args[2:], os.Environ(), os.Stdin, os.Stdout, os.Stderr)
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "install-sudoers" {
		err = installRuntimeSudoers(os.Args[2:])
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "install-signer-sudoers" {
		err = installSignerSudoers(os.Args[2:])
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "export-plan-review" {
		err = exportPlanReview(os.Args[2:])
	} else if err == nil && len(os.Args) > 1 && os.Args[1] == "verify-host-kit-archive" {
		err = verifyHostKitArchive(os.Args[2:])
	} else if err == nil {
		err = run(os.Args[1:], os.Environ(), os.Stdin, os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "deus-aws-bootstrap: %v\n", err)
		os.Exit(64)
	}
}

func prepareExecution(args, inherited []string) error {
	if err := requireLinuxExecution(); err != nil {
		return err
	}
	uid, gid, err := administrativeIdentity(args, inherited, "prepare-execution", "--qualification-uid", "--qualification-gid")
	if err != nil {
		return err
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	if info, err := os.Lstat(executionRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("qualified execution root exists but is not a direct directory")
		}
		entries, readError := os.ReadDir(executionRoot)
		if readError != nil || len(entries) != 0 {
			return errors.New("qualified execution root must be absent or empty")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect qualified execution root: %w", err)
	} else if err := os.MkdirAll(executionRoot, 0o700); err != nil {
		return fmt.Errorf("create qualified execution root: %w", err)
	}
	if err := os.Chown(executionRoot, uid, gid); err != nil {
		return fmt.Errorf("assign qualified execution root: %w", err)
	}
	if err := os.Chmod(executionRoot, 0o700); err != nil {
		return fmt.Errorf("protect qualified execution root: %w", err)
	}
	return nil
}

func sealExecution(args, inherited []string) error {
	if err := requireLinuxExecution(); err != nil {
		return err
	}
	if len(args) != 8 {
		return errors.New("seal-execution requires qualification and runtime UID/GID arguments")
	}
	qualificationUID, _, err := administrativeIdentity(args[:4], inherited, "seal-execution", "--qualification-uid", "--qualification-gid")
	if err != nil {
		return err
	}
	runtimeUID, runtimeGID, err := parseNamedIdentity(args[4:], "--runtime-uid", "--runtime-gid")
	if err != nil {
		return err
	}
	if runtimeUID == qualificationUID {
		return errors.New("runtime UID must be distinct from the qualification UID")
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	candidatePath := filepath.Join(executionRoot, "artifacts", "bootstrap-candidate.json")
	if err := verifyLauncherBinding(
		candidatePath,
		launcherPath,
		filepath.Join(executionRoot, "artifacts", "deus-aws-bootstrap"),
		filepath.Join(executionRoot, "security", "bootstrap-qualification-trust.json"),
		expectedTrustSHA256,
		nodePath,
	); err != nil {
		return err
	}
	validateSealedCopy, err := prepareExecutionTreeForSeal(executionRoot, sourceManifestPath, candidatePath, qualificationUID)
	if err != nil {
		return err
	}
	// Recheck the source binding after pruning and exact inventory capture. The
	// fresh root-owned copy is independently revalidated below before publish.
	if err := verifyLauncherBinding(
		candidatePath,
		launcherPath,
		filepath.Join(executionRoot, "artifacts", "deus-aws-bootstrap"),
		filepath.Join(executionRoot, "security", "bootstrap-qualification-trust.json"),
		expectedTrustSHA256,
		nodePath,
	); err != nil {
		return err
	}
	// Outputs are deliberately returned to the operator only after all other
	// snapshot paths have been captured in a root-owned, non-writable inode graph.
	if err := os.MkdirAll(installRoot, 0o755); err != nil {
		return fmt.Errorf("create bootstrap trust domain: %w", err)
	}
	if err := os.Chown(installRoot, 0, 0); err != nil {
		return fmt.Errorf("own bootstrap trust domain: %w", err)
	}
	if err := os.Chmod(installRoot, 0o755); err != nil {
		return fmt.Errorf("protect bootstrap trust domain: %w", err)
	}
	if err := requireRootOwnedDirectory(installRoot); err != nil {
		return err
	}
	if err := requireRootOwnedRegularFile(nodePath, true); err != nil {
		return err
	}
	if err := requireRootOwnedRegularFile(runtimeProvenancePath, false); err != nil {
		return err
	}
	for _, required := range []string{
		"scripts/credentialed-bootstrap-stage1.mjs",
		"security/bootstrap-qualification-trust.json",
		"artifacts/bootstrap-candidate.json",
		"artifacts/local-gate-evidence.json",
		"artifacts/security-contract-evidence.json",
		"artifacts/bootstrap-pulumi-home/plugins/resource-aws-v7.27.0",
		"dist-management-seed",
		"dist-management-seed-policy",
		"node_modules",
		"onboarding.local.json",
		"Pulumi.management.yaml",
	} {
		if _, err := os.Lstat(filepath.Join(executionRoot, required)); err != nil {
			return fmt.Errorf("qualified execution snapshot is incomplete at %s: %w", required, err)
		}
	}
	for _, output := range []string{
		filepath.Join(executionRoot, "artifacts", "pulumi-plans"),
		filepath.Join(executionRoot, "artifacts", "runtime-output"),
	} {
		if err := requireEmptyDirectory(output); err != nil {
			return err
		}
	}
	staging := fmt.Sprintf("%s.sealing.%d", executionRoot, os.Getpid())
	unsealed := fmt.Sprintf("%s.unsealed.%d", executionRoot, os.Getpid())
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("remove stale sealing root: %w", err)
	}
	if err := copySealedTree(executionRoot, staging, qualificationUID, runtimeGID); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	if err := validateSealedCopy(staging, os.Geteuid()); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("fresh sealed snapshot differs from the qualified inventory: %w", err)
	}
	if err := verifyLauncherBinding(
		filepath.Join(staging, "artifacts", "bootstrap-candidate.json"),
		launcherPath,
		filepath.Join(staging, "artifacts", "deus-aws-bootstrap"),
		filepath.Join(staging, "security", "bootstrap-qualification-trust.json"),
		expectedTrustSHA256,
		nodePath,
	); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	if err := installTrustedFile(
		filepath.Join(staging, "scripts", "credentialed-bootstrap-stage1.mjs"),
		stage1Path,
		0o444,
		expectedStage1SHA256,
	); err != nil {
		return err
	}
	if err := installRuntimeIdentity(runtimeUID, runtimeGID); err != nil {
		return err
	}
	if err := installTrustedFile(
		filepath.Join(staging, "security", "bootstrap-qualification-trust.json"),
		trustPath,
		0o444,
		expectedTrustSHA256,
	); err != nil {
		return err
	}
	if err := os.Rename(executionRoot, unsealed); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("quarantine mutable execution root: %w", err)
	}
	if err := os.Rename(staging, executionRoot); err != nil {
		_ = os.Rename(unsealed, executionRoot)
		_ = os.RemoveAll(staging)
		return fmt.Errorf("publish sealed execution root: %w", err)
	}
	published = true
	if err := os.RemoveAll(unsealed); err != nil {
		return fmt.Errorf("remove quarantined execution root: %w", err)
	}
	for _, output := range []string{
		filepath.Join(executionRoot, "artifacts", "pulumi-plans"),
		filepath.Join(executionRoot, "artifacts", "runtime-output"),
	} {
		if err := os.Chown(output, runtimeUID, runtimeGID); err != nil {
			return fmt.Errorf("assign runtime output %s: %w", output, err)
		}
		if err := os.Chmod(output, 0o700); err != nil {
			return fmt.Errorf("protect runtime output %s: %w", output, err)
		}
	}
	if err := retireQualificationTooling(qualificationToolingPaths()); err != nil {
		return err
	}
	return nil
}

func qualificationToolingPaths() []string {
	return []string{
		installRoot + "/qualification",
		installRoot + "/qualification-bin",
		installRoot + "/toolchains/go",
	}
}

func retireQualificationTooling(paths []string) error {
	for _, value := range paths {
		info, err := os.Lstat(value)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect qualification-only tooling %s: %w", value, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("qualification-only tooling %s is not a direct directory", value)
		}
		if err := os.RemoveAll(value); err != nil {
			return fmt.Errorf("retire qualification-only tooling %s: %w", value, err)
		}
	}
	return requireQualificationToolingRetired(paths)
}

func requireQualificationToolingRetired(paths []string) error {
	for _, value := range paths {
		if _, err := os.Lstat(value); err == nil {
			return fmt.Errorf("qualification-only tooling remains installed at %s", value)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect retired qualification-only tooling %s: %w", value, err)
		}
	}
	return nil
}

func administrativeIdentity(args, inherited []string, operation, uidFlag, gidFlag string) (int, int, error) {
	if os.Geteuid() != 0 {
		return 0, 0, fmt.Errorf("%s must run as root before any AWS session exists", operation)
	}
	uid, gid, err := parseNamedIdentity(args, uidFlag, gidFlag)
	if err != nil {
		return 0, 0, err
	}
	for _, entry := range inherited {
		name, value, found := strings.Cut(entry, "=")
		if found && value != "" && (strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "PULUMI_")) {
			return 0, 0, fmt.Errorf("%s refuses credential variable %s", operation, name)
		}
	}
	return uid, gid, nil
}

func parseNamedIdentity(args []string, uidFlag, gidFlag string) (int, int, error) {
	if len(args) != 4 || args[0] != uidFlag || args[2] != gidFlag {
		return 0, 0, fmt.Errorf("requires %s <uid> %s <gid>", uidFlag, gidFlag)
	}
	uid, err := parseIdentity(args[1], strings.TrimPrefix(uidFlag, "--"))
	if err != nil {
		return 0, 0, err
	}
	gid, err := parseIdentity(args[3], strings.TrimPrefix(gidFlag, "--"))
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func parseIdentity(value, label string) (int, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive decimal integer", label)
	}
	return int(parsed), nil
}

func requireEmptyDirectory(value string) error {
	info, err := os.Lstat(value)
	if err != nil {
		return fmt.Errorf("runtime output directory %s is missing: %w", value, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime output path %s is not a direct directory", value)
	}
	entries, err := os.ReadDir(value)
	if err != nil {
		return fmt.Errorf("inspect runtime output %s: %w", value, err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("runtime output directory %s must be empty before sealing", value)
	}
	return nil
}

func installTrustedFile(source, destination string, mode os.FileMode, expectedSHA256 string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("trusted input %s is not a direct regular file", source)
	}
	contents, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read trusted input %s: %w", source, err)
	}
	observed := fmt.Sprintf("%x", sha256.Sum256(contents))
	if len(expectedSHA256) != 64 || observed != expectedSHA256 {
		return fmt.Errorf("trusted input %s does not match the native launcher's pinned digest", source)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create trust directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".deus-install-")
	if err != nil {
		return fmt.Errorf("create trusted temporary: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write trusted temporary: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync trusted temporary: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close trusted temporary: %w", err)
	}
	if err := os.Chown(temporaryName, 0, 0); err != nil {
		return fmt.Errorf("own trusted temporary: %w", err)
	}
	if err := os.Chmod(temporaryName, mode); err != nil {
		return fmt.Errorf("protect trusted temporary: %w", err)
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return fmt.Errorf("install trusted file: %w", err)
	}
	return nil
}

func installRuntimeIdentity(uid, gid int) error {
	temporary, err := os.CreateTemp(installRoot, ".deus-runtime-identity-")
	if err != nil {
		return fmt.Errorf("create runtime identity temporary: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := fmt.Fprintf(temporary, "%d:%d\n", uid, gid); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write runtime identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync runtime identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close runtime identity: %w", err)
	}
	if err := os.Chown(temporaryName, 0, 0); err != nil {
		return fmt.Errorf("own runtime identity: %w", err)
	}
	if err := os.Chmod(temporaryName, 0o444); err != nil {
		return fmt.Errorf("protect runtime identity: %w", err)
	}
	if err := os.Rename(temporaryName, runtimeIdentityPath); err != nil {
		return fmt.Errorf("install runtime identity: %w", err)
	}
	return nil
}

func copySealedTree(source, destination string, expectedSourceUID, sealedGID int) error {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return fmt.Errorf("create root-owned sealing directory: %w", err)
	}
	if err := os.Chown(destination, os.Geteuid(), sealedGID); err != nil {
		return fmt.Errorf("assign sealed root group: %w", err)
	}
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		return fmt.Errorf("open source snapshot root: %w", err)
	}
	defer sourceRoot.Close()
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		return fmt.Errorf("open sealed snapshot root: %w", err)
	}
	defer destinationRoot.Close()

	copiedEntries := 0
	var copiedBytes int64
	var copyDirectory func(string) error
	copyDirectory = func(relativeDirectory string) error {
		directory, err := sourceRoot.Open(relativeDirectory)
		if err != nil {
			return fmt.Errorf("open snapshot directory %s: %w", relativeDirectory, err)
		}
		info, statError := directory.Stat()
		if statError != nil {
			_ = directory.Close()
			return fmt.Errorf("stat snapshot directory %s: %w", relativeDirectory, statError)
		}
		owner, ownerOK := fileUID(info)
		if !info.IsDir() || !ownerOK || int(owner) != expectedSourceUID {
			_ = directory.Close()
			return fmt.Errorf("snapshot path %s is not an operator-owned directory", relativeDirectory)
		}
		entries, readError := directory.ReadDir(-1)
		closeError := directory.Close()
		if readError != nil {
			return fmt.Errorf("read snapshot directory %s: %w", relativeDirectory, readError)
		}
		if closeError != nil {
			return fmt.Errorf("close snapshot directory %s: %w", relativeDirectory, closeError)
		}
		for _, entry := range entries {
			copiedEntries++
			if copiedEntries > sealMaximumEntries {
				return fmt.Errorf("snapshot exceeds %d filesystem entries while copying", sealMaximumEntries)
			}
			relativePath := filepath.Join(relativeDirectory, entry.Name())
			if filepath.Clean(relativePath) == filepath.Join("artifacts", "bootstrap-signing-review-bundle.json") {
				return errors.New("snapshot contains the confidential transient signing review bundle")
			}
			info, err := sourceRoot.Lstat(relativePath)
			if err != nil {
				return fmt.Errorf("inspect snapshot path %s: %w", relativePath, err)
			}
			owner, ownerOK := fileUID(info)
			if !ownerOK || int(owner) != expectedSourceUID {
				return fmt.Errorf("snapshot path %s is not operator-owned", relativePath)
			}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				target, err := sourceRoot.Readlink(relativePath)
				if err != nil {
					return fmt.Errorf("read snapshot symlink %s: %w", relativePath, err)
				}
				resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(relativePath), target))
				if filepath.IsAbs(target) || resolvedTarget == ".." || strings.HasPrefix(resolvedTarget, ".."+string(filepath.Separator)) {
					return fmt.Errorf("snapshot symlink %s escapes the execution root", relativePath)
				}
				if _, err := sourceRoot.Stat(relativePath); err != nil {
					return fmt.Errorf("snapshot symlink %s has an unsafe target: %w", relativePath, err)
				}
				if err := destinationRoot.Symlink(target, relativePath); err != nil {
					return fmt.Errorf("copy snapshot symlink %s: %w", relativePath, err)
				}
				if err := os.Lchown(filepath.Join(destination, relativePath), os.Geteuid(), sealedGID); err != nil {
					return fmt.Errorf("assign sealed symlink %s: %w", relativePath, err)
				}
			case info.IsDir():
				if err := destinationRoot.Mkdir(relativePath, 0o700); err != nil {
					return fmt.Errorf("create sealed directory %s: %w", relativePath, err)
				}
				if err := destinationRoot.Chown(relativePath, os.Geteuid(), sealedGID); err != nil {
					return fmt.Errorf("assign sealed directory %s: %w", relativePath, err)
				}
				if err := copyDirectory(relativePath); err != nil {
					return err
				}
				if err := destinationRoot.Chmod(relativePath, 0o550); err != nil {
					return fmt.Errorf("protect sealed directory %s: %w", relativePath, err)
				}
			case info.Mode().IsRegular():
				if info.Size() < 0 || info.Size() > sealMaximumFileSize {
					return fmt.Errorf("snapshot file %s exceeds the per-file size budget", relativePath)
				}
				if err := copySealedFile(sourceRoot, destinationRoot, relativePath, info.Mode().Perm()&0o111 != 0, expectedSourceUID, sealedGID, &copiedBytes); err != nil {
					return err
				}
			default:
				return fmt.Errorf("snapshot contains unsupported path %s", relativePath)
			}
		}
		return nil
	}
	if err := copyDirectory("."); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o550); err != nil {
		return fmt.Errorf("protect sealed root: %w", err)
	}
	return nil
}

func copySealedFile(source, destination *os.Root, relativePath string, executable bool, expectedSourceUID, sealedGID int, copiedBytes *int64) error {
	input, err := source.Open(relativePath)
	if err != nil {
		return fmt.Errorf("open snapshot file %s: %w", relativePath, err)
	}
	defer input.Close()
	inputInfo, err := input.Stat()
	if err != nil {
		return fmt.Errorf("stat snapshot file %s: %w", relativePath, err)
	}
	owner, ownerOK := fileUID(inputInfo)
	if !inputInfo.Mode().IsRegular() || !ownerOK || int(owner) != expectedSourceUID {
		return fmt.Errorf("snapshot path %s is not an operator-owned regular file", relativePath)
	}
	if inputInfo.Size() < 0 || inputInfo.Size() > sealMaximumFileSize {
		return fmt.Errorf("snapshot file %s exceeds the per-file size budget", relativePath)
	}
	if *copiedBytes > sealMaximumTreeSize-inputInfo.Size() {
		return errors.New("snapshot exceeds the total byte budget while copying")
	}
	*copiedBytes += inputInfo.Size()
	output, err := destination.OpenFile(relativePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return fmt.Errorf("create sealed file %s: %w", relativePath, err)
	}
	if _, err := io.CopyN(output, input, inputInfo.Size()); err != nil {
		_ = output.Close()
		return fmt.Errorf("copy sealed file %s: %w", relativePath, err)
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
		_ = output.Close()
		return fmt.Errorf("snapshot file %s changed size while copying", relativePath)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return fmt.Errorf("sync sealed file %s: %w", relativePath, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close sealed file %s: %w", relativePath, err)
	}
	if err := destination.Chown(relativePath, os.Geteuid(), sealedGID); err != nil {
		return fmt.Errorf("assign sealed file %s: %w", relativePath, err)
	}
	mode := os.FileMode(0o440)
	if executable {
		mode = 0o550
	}
	if err := destination.Chmod(relativePath, mode); err != nil {
		return fmt.Errorf("protect sealed file %s: %w", relativePath, err)
	}
	return nil
}

func verifyLauncherBinding(candidatePath, installedPath, snapshotPath, qualificationTrustPath, expectedTrustDigest, installedNodePath string) error {
	contents, err := os.ReadFile(candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate launcher binding: %w", err)
	}
	candidate, err := decodeJSONObject(contents)
	if err != nil {
		return fmt.Errorf("parse candidate launcher binding: %w", err)
	}
	candidateDigest, ok := candidate["candidateDigest"].(string)
	if !ok || !isSHA256(candidateDigest) {
		return errors.New("candidate digest is invalid")
	}
	signature, ok := candidate["signature"].(map[string]any)
	if !ok {
		return errors.New("candidate signature is invalid")
	}
	subject := make(map[string]any, len(candidate)-2)
	for key, value := range candidate {
		if key != "candidateDigest" && key != "signature" {
			subject[key] = value
		}
	}
	canonical, err := canonicalJSON(subject)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != candidateDigest {
		return errors.New("candidate digest does not match its signed subject")
	}
	trustContents, err := os.ReadFile(qualificationTrustPath)
	if err != nil {
		return fmt.Errorf("read qualification trust: %w", err)
	}
	if !isSHA256(expectedTrustDigest) || fmt.Sprintf("%x", sha256.Sum256(trustContents)) != expectedTrustDigest {
		return errors.New("qualification trust does not match the native launcher's pin")
	}
	var trust struct {
		APIVersion    string `json:"apiVersion"`
		Configured    bool   `json:"configured"`
		Algorithm     string `json:"algorithm"`
		KeyID         string `json:"keyId"`
		PublicKeySPKI string `json:"publicKeySpki"`
	}
	if err := json.Unmarshal(trustContents, &trust); err != nil {
		return fmt.Errorf("parse qualification trust: %w", err)
	}
	publicDER, err := base64.RawURLEncoding.DecodeString(trust.PublicKeySPKI)
	if err != nil {
		return errors.New("qualification trust public key is invalid")
	}
	publicValue, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return errors.New("qualification trust public key is invalid")
	}
	publicKey, ok := publicValue.(ed25519.PublicKey)
	if !ok || trust.APIVersion != "security.deus.dev/bootstrap-qualification-trust/v1" || !trust.Configured || trust.Algorithm != "Ed25519" || trust.KeyID != fmt.Sprintf("%x", sha256.Sum256(publicDER)) {
		return errors.New("qualification trust is not a configured Ed25519 root")
	}
	signingKeyID, _ := candidate["signingKeyId"].(string)
	signatureAlgorithm, _ := signature["algorithm"].(string)
	signatureKeyID, _ := signature["keyId"].(string)
	signatureValue, _ := signature["value"].(string)
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureValue)
	if err != nil || signingKeyID != trust.KeyID || signatureAlgorithm != "Ed25519" || signatureKeyID != trust.KeyID || !ed25519.Verify(publicKey, []byte("security.deus.dev/bootstrap-candidate/v1:"+candidateDigest), signatureBytes) {
		return errors.New("candidate signature does not match the qualification trust")
	}
	generatedAt, _ := candidate["generatedAt"].(string)
	generated, err := time.Parse(time.RFC3339Nano, generatedAt)
	now := time.Now()
	if err != nil || generated.After(now.Add(time.Minute)) || now.Sub(generated) > 24*time.Hour {
		return errors.New("candidate is outside the 24-hour sealing window")
	}
	nativeLauncher, ok := candidate["nativeLauncher"].(map[string]any)
	if !ok {
		return errors.New("candidate native launcher binding is invalid")
	}
	launcherPathValue, _ := nativeLauncher["path"].(string)
	launcherDigest, _ := nativeLauncher["sha256"].(string)
	if launcherPathValue != "artifacts/deus-aws-bootstrap" || !isSHA256(launcherDigest) {
		return errors.New("candidate native launcher binding is invalid")
	}
	for _, value := range []string{installedPath, snapshotPath} {
		digest, err := sha256File(value)
		if err != nil {
			return err
		}
		if digest != launcherDigest {
			return fmt.Errorf("native launcher %s is stale or not candidate-bound", value)
		}
	}
	runtimeValue, ok := candidate["runtime"].(map[string]any)
	if !ok {
		return errors.New("candidate runtime binding is invalid")
	}
	executables, ok := runtimeValue["executables"].([]any)
	if !ok {
		return errors.New("candidate executable inventory is invalid")
	}
	var nodeBinding map[string]any
	for _, entry := range executables {
		record, recordOK := entry.(map[string]any)
		if recordOK && record["name"] == "node" {
			if nodeBinding != nil {
				return errors.New("candidate contains duplicate Node bindings")
			}
			nodeBinding = record
		}
	}
	if nodeBinding == nil || nodeBinding["path"] != installedNodePath || nodeBinding["realPath"] != installedNodePath {
		return errors.New("candidate Node binding does not use the fixed installed runtime")
	}
	nodeDigest, _ := nodeBinding["sha256"].(string)
	observedNodeDigest, err := sha256File(installedNodePath)
	if err != nil || !isSHA256(nodeDigest) || observedNodeDigest != nodeDigest {
		return errors.New("installed Node is stale or not candidate-bound")
	}
	return nil
}

func decodeJSONObject(contents []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil || result == nil {
		return nil, errors.New("document is not a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("document contains trailing JSON")
	}
	return result, nil
}

func canonicalJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	var writeValue func(any) error
	writeValue = func(current any) error {
		switch typed := current.(type) {
		case nil:
			output.WriteString("null")
		case bool:
			if typed {
				output.WriteString("true")
			} else {
				output.WriteString("false")
			}
		case string:
			var encoded bytes.Buffer
			encoder := json.NewEncoder(&encoded)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(typed); err != nil {
				return err
			}
			output.Write(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
		case json.Number:
			raw := typed.String()
			if raw == "" || (len(raw) > 1 && raw[0] == '0') {
				return errors.New("canonical JSON number is not a minimal nonnegative integer")
			}
			for _, character := range raw {
				if character < '0' || character > '9' {
					return errors.New("canonical JSON number is not a minimal nonnegative integer")
				}
			}
			value, err := strconv.ParseUint(raw, 10, 53)
			if err != nil || value > 9_007_199_254_740_991 {
				return errors.New("canonical JSON number exceeds the JavaScript safe-integer range")
			}
			output.WriteString(raw)
		case []any:
			output.WriteByte('[')
			for index, entry := range typed {
				if index > 0 {
					output.WriteByte(',')
				}
				if err := writeValue(entry); err != nil {
					return err
				}
			}
			output.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			output.WriteByte('{')
			for index, key := range keys {
				if index > 0 {
					output.WriteByte(',')
				}
				if err := writeValue(key); err != nil {
					return err
				}
				output.WriteByte(':')
				if err := writeValue(typed[key]); err != nil {
					return err
				}
			}
			output.WriteByte('}')
		default:
			return fmt.Errorf("unsupported canonical JSON value %T", current)
		}
		return nil
	}
	if err := writeValue(value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func sha256File(value string) (string, error) {
	contents, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("read digest input %s: %w", value, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(contents)), nil
}

func requireLinuxExecution() error {
	if runtime.GOOS != "linux" {
		return errors.New("credential execution and host sealing require a dedicated Linux host")
	}
	return nil
}

func run(args, inherited []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || (args[0] != "bootstrap" && args[0] != "access-provisioner" && args[0] != "organization-recovery") {
		return errors.New("first argument must be bootstrap, access-provisioner, or organization-recovery")
	}
	for _, arg := range args[1:] {
		if arg == "--root" || strings.HasPrefix(arg, "--root=") {
			return errors.New("credentialed execution root is fixed and cannot be overridden")
		}
	}
	if err := requireLinuxExecution(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("credential execution as OS root is forbidden")
	}
	if err := requirePtraceIsolation(); err != nil {
		return err
	}
	if err := rejectInheritedCredentialMaterial(inherited); err != nil {
		return err
	}
	filteredArgs, credentialFD, err := extractCredentialFD(args)
	if err != nil {
		return err
	}
	args = filteredArgs
	environment, err := environmentMap(inherited)
	if err != nil {
		return err
	}
	for _, path := range []string{
		installRoot,
		executionRoot,
		pulumiHome,
	} {
		if err := requireRootOwnedDirectory(path); err != nil {
			return err
		}
	}
	if err := requireRootOwnedRegularFile(nodePath, true); err != nil {
		return err
	}
	for _, path := range []string{stage1Path, trustPath, runtimeIdentityPath, runtimeProvenancePath} {
		if err := requireRootOwnedRegularFile(path, false); err != nil {
			return err
		}
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	if err := requireQualificationToolingRetired(qualificationToolingPaths()); err != nil {
		return err
	}
	runtimeIdentity, err := os.ReadFile(runtimeIdentityPath)
	if err != nil {
		return fmt.Errorf("read sealed runtime identity: %w", err)
	}
	if err := validateRuntimeIdentity(runtimeIdentity, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	if err := requireExclusiveRuntimeService(); err != nil {
		return err
	}
	session, err := readCredentialFD(credentialFD, args[0], time.Now().UTC())
	if err != nil {
		return err
	}
	broker, err := startCredentialBroker(session)
	if err != nil {
		return err
	}
	defer broker.close()

	temporaryRoot, err := trustedTemporaryRoot()
	if err != nil {
		return err
	}
	home, err := os.MkdirTemp(temporaryRoot, "deus-bootstrap-home-")
	if err != nil {
		return fmt.Errorf("create isolated home: %w", err)
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return fmt.Errorf("protect isolated home: %w", err)
	}
	temporary := filepath.Join(home, "tmp")
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return fmt.Errorf("create isolated temporary directory: %w", err)
	}

	childEnvironment := buildChildEnvironment(environment, home, temporary, args[0], broker)
	commandArgs := append([]string{stage1Path, args[0]}, args[1:]...)
	command := exec.Command(nodePath, commandArgs...)
	command.Dir = executionRoot
	command.Env = childEnvironment
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if args[0] == "bootstrap" {
		capabilityReader, capabilityWriter, err := os.Pipe()
		if err != nil {
			return fmt.Errorf("create Pulumi broker capability pipe: %w", err)
		}
		if _, err := capabilityWriter.WriteString(broker.pulumiToken + "\n"); err != nil {
			_ = capabilityReader.Close()
			_ = capabilityWriter.Close()
			return fmt.Errorf("write Pulumi broker capability: %w", err)
		}
		if err := capabilityWriter.Close(); err != nil {
			_ = capabilityReader.Close()
			return fmt.Errorf("close Pulumi broker capability pipe: %w", err)
		}
		defer capabilityReader.Close()
		command.ExtraFiles = []*os.File{capabilityReader}
	}
	// Landlock ABI v1 applies to the calling thread and its future children.
	// Keep restriction and fork/exec on one OS thread so the Node verifier
	// necessarily inherits the execute allowlist even though the Go runtime is
	// otherwise multithreaded.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := confineCredentialExecution(home); err != nil {
		return err
	}
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("trusted verifier exited with status %d", exitError.ExitCode())
		}
		return fmt.Errorf("start trusted verifier: %w", err)
	}
	return nil
}

func runSigningReview(args, inherited []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := requireLinuxExecution(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("independent signing review as OS root is forbidden")
	}
	if err := requireSignerServicePhase(signingReviewCgroup); err != nil {
		return err
	}
	if len(args) != 2 || args[0] != "--bundle-fd" || args[1] != "0" {
		return errors.New("signing-review requires the root-sealed service bundle descriptor")
	}
	if err := validateSigningEnvironment(inherited); err != nil {
		return err
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve signing-review working directory: %w", err)
	}
	realWorkingDirectory, err := filepath.EvalSymlinks(workingDirectory)
	if err != nil || filepath.Clean(realWorkingDirectory) != executionRoot {
		return errors.New("signing-review must run from the fixed execution root")
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	for _, path := range []string{
		nodePath,
		signingStage0Path,
		sourceManifestPath,
		releaseIdentityPath,
	} {
		if err := requireRootOwnedRegularFile(path, path == nodePath); err != nil {
			return err
		}
	}
	bundle, err := readSealedSigningBundle(stdin)
	if err != nil {
		return err
	}
	sealedBundle, err := createSealedBundle(bundle)
	for index := range bundle {
		bundle[index] = 0
	}
	if err != nil {
		return err
	}
	defer sealedBundle.Close()
	temporaryRoot, err := trustedTemporaryRoot()
	if err != nil {
		return err
	}
	home, err := os.MkdirTemp(temporaryRoot, "deus-signing-review-")
	if err != nil {
		return fmt.Errorf("create isolated signer home: %w", err)
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return fmt.Errorf("protect isolated signer home: %w", err)
	}
	command := exec.Command(nodePath, signingStage0Path)
	command.Dir = executionRoot
	command.Env = []string{
		"DEUS_NATIVE_SIGNING_LAUNCHER=v1",
		"DEUS_PRODUCTION_QUALIFICATION=1",
		"DEUS_SIGNING_BUNDLE_FD=3",
		"DEUS_SIGNING_REVIEW_PHASE=review",
		"HOME=" + home,
		"LANG=C",
		"NPM_CONFIG_GLOBALCONFIG=/dev/null",
		"NPM_CONFIG_USERCONFIG=/dev/null",
		"PATH=" + installRoot + "/bin:" + installRoot + "/qualification-bin:" + installRoot + "/toolchains/go/bin:/usr/bin:/bin",
		"PULUMI_HOME=" + pulumiHome,
	}
	command.ExtraFiles = []*os.File{sealedBundle}
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("signing stage zero exited with status %d", exitError.ExitCode())
		}
		return fmt.Errorf("start signing stage zero: %w", err)
	}
	return nil
}

func runSigningPreparation(args, inherited []string, stdout, stderr io.Writer) error {
	if err := requireLinuxExecution(); err != nil {
		return err
	}
	if os.Geteuid() == 0 || len(args) != 0 {
		return errors.New("signing-prepare requires the isolated unprivileged signer service")
	}
	if err := requireSignerServicePhase(signingPrepareCgroup); err != nil {
		return err
	}
	if err := validateSigningEnvironment(inherited); err != nil {
		return err
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve signing preparation working directory: %w", err)
	}
	realWorkingDirectory, err := filepath.EvalSymlinks(workingDirectory)
	if err != nil || filepath.Clean(realWorkingDirectory) != executionRoot {
		return errors.New("signing preparation must run from the fixed execution root")
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	for _, value := range []string{nodePath, signingStage0Path, sourceManifestPath, releaseIdentityPath} {
		if err := requireRootOwnedRegularFile(value, value == nodePath); err != nil {
			return err
		}
	}
	temporaryRoot, err := trustedTemporaryRoot()
	if err != nil {
		return err
	}
	home, err := os.MkdirTemp(temporaryRoot, "deus-signing-prepare-")
	if err != nil {
		return fmt.Errorf("create isolated signer preparation home: %w", err)
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return fmt.Errorf("protect isolated signer preparation home: %w", err)
	}
	command := exec.Command(nodePath, signingStage0Path, "--prepare")
	command.Dir = executionRoot
	command.Env = []string{
		"DEUS_NATIVE_SIGNING_LAUNCHER=v1",
		"DEUS_PRODUCTION_QUALIFICATION=1",
		"DEUS_SIGNING_REVIEW_PHASE=prepare",
		"HOME=" + home,
		"LANG=C",
		"NPM_CONFIG_GLOBALCONFIG=/dev/null",
		"NPM_CONFIG_USERCONFIG=/dev/null",
		"PATH=" + installRoot + "/bin:" + installRoot + "/qualification-bin:" + installRoot + "/toolchains/go/bin:/usr/bin:/bin",
		"PULUMI_HOME=" + pulumiHome,
	}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("signing preparation stage zero exited with status %d", exitError.ExitCode())
		}
		return fmt.Errorf("start signing preparation stage zero: %w", err)
	}
	return nil
}

func validateSigningEnvironment(entries []string) error {
	for _, entry := range entries {
		name, _, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return errors.New("signing environment contains a malformed entry")
		}
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "AWS_") ||
			strings.HasPrefix(upper, "PULUMI_") ||
			strings.HasPrefix(upper, "NODE_") ||
			strings.HasPrefix(upper, "NPM_") ||
			strings.HasPrefix(upper, "GIT_") ||
			strings.HasPrefix(upper, "LD_") ||
			strings.HasPrefix(upper, "DYLD_") ||
			strings.Contains(upper, "TOKEN") ||
			strings.Contains(upper, "SECRET") ||
			strings.Contains(upper, "CREDENTIAL") ||
			strings.HasSuffix(upper, "_PROXY") ||
			upper == "BASH_ENV" || upper == "ENV" || upper == "SHELLOPTS" {
			return fmt.Errorf("signing review rejects inherited environment variable %s", name)
		}
	}
	return nil
}

func validateRuntimeIdentity(contents []byte, currentUID, currentGID int) error {
	parts := strings.Split(strings.TrimSuffix(string(contents), "\n"), ":")
	if len(parts) != 2 || strings.Contains(string(contents), "\r") || !strings.HasSuffix(string(contents), "\n") {
		return errors.New("sealed runtime identity is malformed")
	}
	expectedUID, err := parseIdentity(parts[0], "runtime UID")
	if err != nil {
		return errors.New("sealed runtime identity is malformed")
	}
	expectedGID, err := parseIdentity(parts[1], "runtime GID")
	if err != nil {
		return errors.New("sealed runtime identity is malformed")
	}
	if currentUID != expectedUID || currentGID != expectedGID {
		return errors.New("credential launcher must run as the distinct sealed runtime UID/GID")
	}
	return nil
}

func trustedTemporaryRoot() (string, error) {
	root := "/tmp"
	if runtime.GOOS == "darwin" {
		root = "/private/tmp"
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect trusted temporary root: %w", err)
	}
	uid, ok := fileUID(info)
	if !ok || uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSticky == 0 {
		return "", errors.New("system temporary root is not a root-owned sticky direct directory")
	}
	return root, nil
}

func environmentMap(entries []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return nil, errors.New("inherited environment contains a malformed entry")
		}
		if allowedEnvironment[name] {
			result[name] = value
		}
	}
	return result, nil
}

func buildChildEnvironment(inherited map[string]string, home, temporary, entrypoint string, broker *localCredentialBroker) []string {
	result := map[string]string{
		"AWS_CONTAINER_AUTHORIZATION_TOKEN":           broker.awsToken,
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":          broker.uri,
		"AWS_CONFIG_FILE":                             "/dev/null",
		"AWS_EC2_METADATA_DISABLED":                   "true",
		"AWS_SHARED_CREDENTIALS_FILE":                 "/dev/null",
		"DEUS_NATIVE_CREDENTIAL_LAUNCHER":             "v1",
		"DEUS_EXECUTION_CONFINEMENT":                  "systemd-noexec-landlock-v1",
		"DEUS_QUALIFIED_EXECUTION_ROOT":               executionRoot,
		"HOME":                                        home,
		"PATH":                                        installRoot + "/bin",
		"PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION": "true",
		"PULUMI_HOME":                                 pulumiHome,
		"PULUMI_IGNORE_AMBIENT_PLUGINS":               "true",
		"TMPDIR":                                      temporary,
	}
	if entrypoint == "bootstrap" {
		result["DEUS_PULUMI_BROKER_FD"] = "3"
	}
	for name, value := range inherited {
		if allowedEnvironment[name] && value != "" {
			result[name] = value
		}
	}
	names := make([]string, 0, len(result))
	for name := range result {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]string, 0, len(names))
	for _, name := range names {
		entries = append(entries, name+"="+result[name])
	}
	return entries
}

func requireRootOwnedPath(value string) error {
	clean := filepath.Clean(value)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("trusted path is not absolute: %s", value)
	}
	volume := filepath.VolumeName(clean)
	current := string(filepath.Separator)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	parts := strings.Split(strings.TrimPrefix(clean, current), string(filepath.Separator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("trusted path %s is unavailable: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("trusted path %s contains a symlink", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("trusted path %s is group/other writable", current)
		}
		uid, ok := fileUID(info)
		if !ok || uid != 0 {
			return fmt.Errorf("trusted path %s is not root-owned", current)
		}
	}
	return nil
}

func requireRootOwnedDirectory(value string) error {
	if err := requireRootOwnedPath(value); err != nil {
		return err
	}
	info, err := os.Lstat(value)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("trusted directory %s is not a direct directory", value)
	}
	return nil
}

func requireRootOwnedRegularFile(value string, executable bool) error {
	if err := requireRootOwnedPath(value); err != nil {
		return err
	}
	info, err := os.Lstat(value)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("trusted file %s is not a direct regular file", value)
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("trusted file %s has privileged mode bits", value)
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("trusted executable %s is not executable", value)
	}
	return nil
}

func requireInstalledLauncher() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve running launcher: %w", err)
	}
	real, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("resolve running launcher path: %w", err)
	}
	if filepath.Clean(real) != launcherPath {
		return errors.New("credential launcher is not running from its fixed installed path")
	}
	return requireRootOwnedRegularFile(launcherPath, true)
}

func fileUID(info os.FileInfo) (uint32, bool) {
	return platformFileUID(info)
}

func init() {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		panic("deus-aws-bootstrap supports only Linux and macOS")
	}
}
