//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const runtimeServiceCgroup = "/system.slice/deus-bootstrap-runtime.service"

func runRuntimeService(args, inherited []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("runtime-service requires the host administrator")
	}
	if len(args) == 0 || (args[0] != "bootstrap" && args[0] != "access-provisioner" && args[0] != "organization-recovery") {
		return errors.New("runtime-service requires bootstrap, access-provisioner, or organization-recovery")
	}
	for _, arg := range args[1:] {
		if arg == "--credential-fd" || strings.HasPrefix(arg, "--credential-fd=") {
			return errors.New("runtime-service owns the credential descriptor")
		}
	}
	if err := rejectInheritedCredentialMaterial(inherited); err != nil {
		return err
	}
	if err := requireLockedShadowAccount(); err != nil {
		return err
	}
	input, ok := stdin.(*os.File)
	if !ok {
		return errors.New("runtime-service credential input must be an anonymous pipe")
	}
	if err := requireAnonymousPipe(input, "runtime-service credential input"); err != nil {
		return err
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	if args[0] == "bootstrap" {
		for _, argument := range args[1:] {
			if argument == "--recover-organization-state" || strings.HasPrefix(argument, "--recover-organization-state=") {
				return errors.New("runtime-service requires the AWS-only organization-recovery mode")
			}
		}
		digest, apply, err := applyPlanReviewRequirement(args[1:])
		if err != nil {
			return err
		}
		if apply {
			if err := requireFrozenPlanReview(digest); err != nil {
				return err
			}
		}
	} else if args[0] == "organization-recovery" {
		for _, argument := range args[1:] {
			if argument == "--apply" || argument == "--preview" || argument == "--recover-organization-state" ||
				strings.HasPrefix(argument, "--apply=") || strings.HasPrefix(argument, "--preview=") ||
				strings.HasPrefix(argument, "--recover-organization-state=") {
				return errors.New("organization-recovery owns its exact read-only operation mode")
			}
		}
		recoveryArgs := append([]string{"--recover-organization-state"}, args[1:]...)
		digest, required, err := applyPlanReviewRequirement(recoveryArgs)
		if err != nil {
			return err
		}
		if !required {
			return errors.New("organization-recovery requires frozen plan review")
		}
		if err := requireFrozenPlanReview(digest); err != nil {
			return err
		}
	}
	if err := requireRootOwnedRegularFile("/usr/bin/systemd-run", true); err != nil {
		return err
	}
	mappings, err := credentialExecutableMappings()
	if err != nil {
		return err
	}
	commandArgs := runtimeServiceCommandArgs(mappings, args)
	command := exec.Command("/usr/bin/systemd-run", commandArgs...)
	command.Env = []string{"HOME=/root", "LANG=C", "PATH=/usr/bin:/bin"}
	command.Stdin = input
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run isolated credential service: %w", err)
	}
	return nil
}

func applyPlanReviewRequirement(args []string) (string, bool, error) {
	apply := false
	recoverOrganizationState := false
	digest := ""
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--apply":
			if apply {
				return "", false, errors.New("runtime-service rejects duplicate --apply")
			}
			apply = true
		case strings.HasPrefix(argument, "--apply="):
			return "", false, errors.New("runtime-service requires the exact --apply flag")
		case argument == "--recover-organization-state":
			if recoverOrganizationState {
				return "", false, errors.New("runtime-service rejects duplicate --recover-organization-state")
			}
			recoverOrganizationState = true
		case strings.HasPrefix(argument, "--recover-organization-state="):
			return "", false, errors.New("runtime-service requires the exact --recover-organization-state flag")
		case argument == "--confirm-plan-manifest-digest":
			if digest != "" || index+1 >= len(args) || !isSHA256(args[index+1]) {
				return "", false, errors.New("runtime-service received an invalid plan manifest confirmation")
			}
			index++
			digest = args[index]
		case strings.HasPrefix(argument, "--confirm-plan-manifest-digest="):
			value := strings.TrimPrefix(argument, "--confirm-plan-manifest-digest=")
			if digest != "" || !isSHA256(value) {
				return "", false, errors.New("runtime-service received an invalid plan manifest confirmation")
			}
			digest = value
		}
	}
	if apply && recoverOrganizationState {
		return "", false, errors.New("runtime-service rejects combined apply and organization recovery")
	}
	if (apply || recoverOrganizationState) && digest == "" {
		return "", false, errors.New("runtime-service apply/recovery requires a frozen plan manifest digest")
	}
	return digest, apply || recoverOrganizationState, nil
}

func requireLockedShadowAccount() error {
	contents, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return fmt.Errorf("read runtime shadow account: %w", err)
	}
	return validateLockedShadowAccount(contents)
}

func validateLockedShadowAccount(contents []byte) error {
	found := false
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 || fields[0] != "deus-runtime" {
			continue
		}
		if found || len(fields) != 9 ||
			(!strings.HasPrefix(fields[1], "!") && !strings.HasPrefix(fields[1], "*")) {
			return errors.New("runtime shadow account must be uniquely password-locked")
		}
		found = true
	}
	if !found {
		return errors.New("runtime shadow account is unavailable")
	}
	return nil
}

func runtimeServiceCommandArgs(mappings, args []string) []string {
	commandArgs := []string{
		"--quiet",
		"--pipe",
		"--wait",
		"--collect",
		"--unit=deus-bootstrap-runtime",
		"--service-type=exec",
		"--property=User=deus-runtime",
		"--property=Group=deus-runtime",
		"--property=KillMode=control-group",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=PrivateDevices=yes",
		"--property=ProtectProc=invisible",
		"--property=ProcSubset=all",
		"--property=ProtectHome=yes",
		"--property=ProtectSystem=strict",
		"--property=ProtectKernelTunables=yes",
		"--property=ProtectKernelModules=yes",
		"--property=ProtectKernelLogs=yes",
		"--property=ProtectControlGroups=yes",
		"--property=ProtectClock=yes",
		"--property=RestrictSUIDSGID=yes",
		"--property=RestrictNamespaces=yes",
		"--property=RestrictRealtime=yes",
		"--property=SystemCallFilter=~@mount memfd_create",
		"--property=RestrictAddressFamilies=AF_INET AF_INET6",
		"--property=InaccessiblePaths=-/run/dbus -/run/systemd/private -/run/user",
		"--property=SystemCallArchitectures=native",
		"--property=CapabilityBoundingSet=",
		"--property=AmbientCapabilities=",
		"--property=UMask=0077",
		"--property=NoExecPaths=/",
		"--property=ReadWritePaths=" + executionRoot + "/artifacts/pulumi-plans",
		"--property=ReadWritePaths=" + executionRoot + "/artifacts/runtime-output",
	}
	for _, value := range mappings {
		commandArgs = append(commandArgs, "--property=ExecPaths="+value)
	}
	commandArgs = append(commandArgs, "--", launcherPath, args[0], "--credential-fd", "0")
	commandArgs = append(commandArgs, args[1:]...)
	return commandArgs
}

func requireExclusiveRuntimeService() error {
	contents, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !inRuntimeServiceCgroup(contents) {
		return errors.New("credential execution requires the fixed one-shot system service")
	}
	if err := requireLockedRuntimeAccount(os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("inventory runtime UID processes: %w", err)
	}
	peers := make([]int, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) == 4 && fields[1] == strconv.Itoa(os.Geteuid()) {
				peers = append(peers, pid)
			}
		}
	}
	if len(peers) != 0 {
		return fmt.Errorf("runtime UID is not exclusive; peer processes exist: %v", peers)
	}
	return nil
}

func inRuntimeServiceCgroup(contents []byte) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		if line == "0::"+runtimeServiceCgroup {
			return true
		}
	}
	return false
}

func requireLockedRuntimeAccount(uid, gid int) error {
	contents, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Errorf("read runtime account: %w", err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("inventory runtime supplementary groups: %w", err)
	}
	return validateLockedRuntimeAccount(contents, uid, gid, groups)
}

func validateLockedRuntimeAccount(contents []byte, uid, gid int, groups []int) error {
	uidText := strconv.Itoa(uid)
	found := false
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[2] != uidText {
			continue
		}
		if found || fields[0] != "deus-runtime" || fields[3] != strconv.Itoa(gid) || fields[5] != "/nonexistent" ||
			(fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin") {
			return errors.New("runtime UID must belong exclusively to the locked non-login deus-runtime account")
		}
		found = true
	}
	if !found {
		return errors.New("sealed runtime UID has no local account")
	}
	for _, supplementary := range groups {
		if supplementary != gid {
			return fmt.Errorf("runtime account has forbidden supplementary group %d", supplementary)
		}
	}
	return nil
}
