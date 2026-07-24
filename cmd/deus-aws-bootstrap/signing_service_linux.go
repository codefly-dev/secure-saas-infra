//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	signingPrepareCgroup = "/system.slice/deus-bootstrap-signing-prepare.service"
	signingReviewCgroup  = "/system.slice/deus-bootstrap-signing-review.service"
	signingReviewBundle  = "/var/lib/deus-bootstrap/signing-review-bundle.json"
)

func runSigningReviewService(args, inherited []string, stdout, stderr io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("signing-review-service requires the host administrator")
	}
	uid, gid, err := parseNamedIdentity(args, "--signer-uid", "--signer-gid")
	if err != nil {
		return err
	}
	if err := validateSigningEnvironment(inherited); err != nil {
		return err
	}
	transaction, err := acquireSigningTransaction()
	if err != nil {
		return err
	}
	defer releaseSigningTransaction(transaction)
	if err := requireDedicatedSignerIdentity(uid, gid); err != nil {
		return err
	}
	if err := requireSignerExecutionRoot(uid, gid); err != nil {
		return err
	}
	if err := requireSignerBundle(); err != nil {
		return err
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	if err := requireRootOwnedRegularFile("/usr/bin/systemd-run", true); err != nil {
		return err
	}
	if err := runSignerPhase("prepare", uid, gid, nil, stdout, stderr); err != nil {
		return err
	}
	if err := requireNoProcessesForUID(uid); err != nil {
		return fmt.Errorf("signer preparation left an external process: %w", err)
	}
	manifestContents, err := os.ReadFile(sourceManifestPath)
	if err != nil {
		return fmt.Errorf("read signer source manifest: %w", err)
	}
	manifest, err := parseSignerSourceManifest(manifestContents)
	if err != nil {
		return err
	}
	if err := replaceSignerReviewTreeWithSnapshot(executionRoot, manifest, uid, gid); err != nil {
		return err
	}
	if err := requireNoProcessesForUID(uid); err != nil {
		return fmt.Errorf("signer identity restarted during snapshot capture: %w", err)
	}
	if err := requirePreparedSignerReviewTree(executionRoot, sourceManifestPath); err != nil {
		return err
	}
	bundle, err := consumeRootSignerBundle()
	if err != nil {
		return err
	}
	sealed, err := createSealedBundle(bundle)
	for index := range bundle {
		bundle[index] = 0
	}
	if err != nil {
		return err
	}
	defer sealed.Close()
	reviewErr := runSignerPhase("review", uid, gid, sealed, stdout, stderr)
	processErr := requireNoProcessesForUID(uid)
	if reviewErr != nil {
		return reviewErr
	}
	if processErr != nil {
		return fmt.Errorf("signer review left an external process: %w", processErr)
	}
	return nil
}

func requireSignerExecutionRoot(uid, gid int) error {
	info, err := os.Lstat(executionRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("signer execution root must be a private direct directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return errors.New("signer execution root owner differs from the selected signer identity")
	}
	return nil
}

func runSignerPhase(phase string, uid, gid int, stdin *os.File, stdout, stderr io.Writer) error {
	commandArgs := signerServiceCommandArgs(phase, uid, gid)
	command := exec.Command("/usr/bin/systemd-run", commandArgs...)
	command.Env = []string{"HOME=/root", "LANG=C", "PATH=/usr/bin:/bin"}
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run isolated signer %s service: %w", phase, err)
	}
	return nil
}

func signerServiceCommandArgs(phase string, uid, gid int) []string {
	unit := "deus-bootstrap-signing-" + phase
	properties := []string{
		"User=" + strconv.Itoa(uid),
		"Group=" + strconv.Itoa(gid),
		"WorkingDirectory=" + executionRoot,
		"SupplementaryGroups=",
		"KillMode=control-group",
		"NoNewPrivileges=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectProc=invisible",
		"ProcSubset=all",
		"ProtectHome=yes",
		"ProtectSystem=strict",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelLogs=yes",
		"ProtectControlGroups=yes",
		"ProtectClock=yes",
		"RestrictSUIDSGID=yes",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"SystemCallArchitectures=native",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"UMask=0077",
		"RuntimeMaxSec=30min",
		"TimeoutStopSec=15s",
	}
	if phase == "prepare" {
		properties = append(properties,
			"PrivateNetwork=no",
			"RestrictAddressFamilies=AF_INET AF_INET6",
			"SystemCallFilter=~@mount",
			"InaccessiblePaths=-/run/dbus -/run/systemd/private -/run/user",
			"ReadWritePaths="+executionRoot,
		)
	} else {
		properties = append(properties,
			"PrivateNetwork=yes",
			"RestrictAddressFamilies=AF_UNIX",
			"SystemCallFilter=~@mount @network-io",
			"ReadOnlyPaths="+executionRoot,
		)
	}
	args := []string{
		"--quiet",
		"--pipe",
		"--wait",
		"--collect",
		"--service-type=exec",
		"--unit=" + unit,
	}
	for _, property := range properties {
		args = append(args, "--property="+property)
	}
	args = append(args, "--", launcherPath)
	if phase == "prepare" {
		args = append(args, "signing-prepare")
	} else {
		args = append(args, "signing-review", "--bundle-fd", "0")
	}
	return args
}

func requireSignerServicePhase(expected string) error {
	contents, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !inExactUnifiedCgroup(contents, expected) {
		return errors.New("signing requires the fixed root-managed service phase")
	}
	return nil
}

func inExactUnifiedCgroup(contents []byte, expected string) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line == "0::"+expected {
			return true
		}
	}
	return false
}

func requireSignerBundle() error {
	if err := requireRootOwnedRegularFile(signingReviewBundle, false); err != nil {
		return err
	}
	info, err := os.Lstat(signingReviewBundle)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o400 {
		return errors.New("signing review bundle source must be root-only mode 0400")
	}
	return nil
}

func readRootSignerBundle() ([]byte, error) {
	file, err := os.OpenFile(signingReviewBundle, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open root-only signing review bundle: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 ||
		info.Size() <= 0 || info.Size() > 100*1024*1024 {
		return nil, errors.New("root-only signing review bundle is unsafe")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 100*1024*1024+1))
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, errors.New("root-only signing review bundle changed or is unreadable")
	}
	return contents, nil
}

func consumeRootSignerBundle() ([]byte, error) {
	contents, readErr := readRootSignerBundle()
	removeErr := os.Remove(signingReviewBundle)
	if readErr != nil {
		return nil, readErr
	}
	if removeErr != nil {
		for index := range contents {
			contents[index] = 0
		}
		return nil, fmt.Errorf("remove consumed signing review bundle: %w", removeErr)
	}
	parent, err := os.Open("/var/lib/deus-bootstrap")
	if err != nil {
		for index := range contents {
			contents[index] = 0
		}
		return nil, fmt.Errorf("open signing bundle parent after consumption: %w", err)
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil || closeErr != nil {
		for index := range contents {
			contents[index] = 0
		}
		return nil, errors.New("persist removal of consumed signing review bundle")
	}
	return contents, nil
}
