//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	landlockCreateRuleset        = 444
	landlockAddRule              = 445
	landlockRestrictSelf         = 446
	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1
	landlockAccessFSExecute      = 1 << 0
	landlockAccessFSReadFile     = 1 << 2
	landlockAccessFSReadDir      = 1 << 3
	oPath                        = 0x200000
	prSetNoNewPrivs              = 38
	fAddSeals                    = 1033
	fGetSeals                    = 1034
	fSealSeal                    = 0x0001
	fSealShrink                  = 0x0002
	fSealGrow                    = 0x0004
	fSealWrite                   = 0x0008
	mfdAllowSealing              = 0x0002
)

type landlockRulesetAttr struct {
	HandledAccessFS uint64
}

type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
	_             uint32
}

func disableProcessDumpability() error {
	const prSetDumpable = 4
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("disable process dumpability: %w", errno)
	}
	return nil
}

func requirePtraceIsolation() error {
	contents, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return fmt.Errorf("require Yama ptrace isolation: %w", err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil || value < 2 {
		return errors.New("credential execution requires kernel.yama.ptrace_scope=2 or 3")
	}
	return nil
}

func createSealedBundle(contents []byte) (*os.File, error) {
	var memfdCreate uintptr
	switch runtime.GOARCH {
	case "amd64":
		memfdCreate = 319
	case "arm64":
		memfdCreate = 279
	default:
		return nil, fmt.Errorf("sealed bundle is unsupported on architecture %s", runtime.GOARCH)
	}
	name, err := syscall.BytePtrFromString("deus-bootstrap-signing-bundle")
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.RawSyscall(memfdCreate, uintptr(unsafe.Pointer(name)), mfdAllowSealing, 0)
	runtime.KeepAlive(name)
	if errno != 0 {
		return nil, fmt.Errorf("create sealed signing bundle: %w", errno)
	}
	file := os.NewFile(fd, "deus-bootstrap-signing-bundle")
	if file == nil {
		_ = syscall.Close(int(fd))
		return nil, errors.New("create sealed signing bundle descriptor")
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write sealed signing bundle: %w", err)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, fd, fAddSeals, fSealWrite|fSealGrow|fSealShrink|fSealSeal); errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("seal signing bundle: %w", errno)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("rewind sealed signing bundle: %w", err)
	}
	return file, nil
}

func readSealedSigningBundle(input io.Reader) ([]byte, error) {
	file, ok := input.(*os.File)
	if !ok {
		return nil, errors.New("signing review input must be a sealed memfd")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 100*1024*1024 {
		return nil, errors.New("signing review sealed memfd is empty, excessive, or invalid")
	}
	seals, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, file.Fd(), fGetSeals, 0)
	if errno != 0 || seals&(fSealWrite|fSealGrow|fSealShrink|fSealSeal) !=
		fSealWrite|fSealGrow|fSealShrink|fSealSeal {
		return nil, errors.New("signing review memfd is not fully sealed")
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
	if err != nil || !strings.HasPrefix(target, "/memfd:deus-bootstrap-signing-bundle") ||
		!strings.HasSuffix(target, " (deleted)") {
		return nil, errors.New("signing review descriptor is not the native anonymous memfd")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 100*1024*1024+1))
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, errors.New("signing review sealed memfd is truncated or unreadable")
	}
	return contents, nil
}

func confineCredentialExecution(home string) error {
	systemRuntime, err := loadBoundSystemRuntimeClosure()
	if err != nil {
		return err
	}
	if err := validateExecutionELFClosure(systemRuntime); err != nil {
		return err
	}
	executables := credentialExecutablePaths()
	readableFiles, readableDirectories := credentialReadablePathPolicy(home)
	for _, binding := range systemRuntime.Loaders {
		executables = append(executables, binding.Path)
		readableFiles = append(readableFiles, binding.Path)
	}
	for _, binding := range systemRuntime.Libraries {
		readableFiles = append(readableFiles, binding.Path)
	}
	readableFiles = existingResolvedPaths(readableFiles)
	readableDirectories = existingResolvedPaths(readableDirectories)
	return restrictFileAccess(executables, readableFiles, readableDirectories)
}

func credentialReadablePathPolicy(home string) ([]string, []string) {
	return []string{
			stage1Path,
			trustPath,
			runtimeIdentityPath,
			runtimeProvenancePath,
			"/dev/null",
			"/dev/random",
			"/dev/urandom",
			"/etc/gai.conf",
			"/etc/group",
			"/etc/host.conf",
			"/etc/hosts",
			"/etc/ld.so.cache",
			"/etc/localtime",
			"/etc/machine-id",
			"/etc/nsswitch.conf",
			"/etc/passwd",
			"/etc/resolv.conf",
			"/etc/services",
		}, []string{
			executionRoot,
			home,
			installRoot + "/toolchains/aws-cli/v2/current/dist",
			"/etc/ssl/certs",
			"/usr/share/ca-certificates",
			"/usr/share/zoneinfo",
		}
}

func credentialExecutablePaths() []string {
	return []string{
		nodePath,
		launcherPath,
		installRoot + "/bin/aws",
		installRoot + "/bin/pulumi",
		installRoot + "/bin/pulumi-analyzer-policy",
		installRoot + "/bin/pulumi-language-nodejs",
		installRoot + "/bin/pulumi-resource-pulumi-nodejs",
		pulumiHome + "/plugins/resource-aws-v7.27.0/pulumi-resource-aws",
	}
}

func existingResolvedPaths(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		resolved, err := filepath.EvalSymlinks(value)
		if err != nil || seen[resolved] {
			continue
		}
		seen[resolved] = true
		result = append(result, resolved)
	}
	sort.Strings(result)
	return result
}

func restrictExecutablePaths(paths []string) error {
	return restrictFileAccess(paths, nil, nil)
}

func restrictFileAccess(executablePaths, readableFiles, readableDirectories []string) error {
	abi, _, errno := syscall.RawSyscall6(
		landlockCreateRuleset,
		0,
		0,
		landlockCreateRulesetVersion,
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("require Linux Landlock executable confinement: %w", errno)
	}
	if abi < 1 {
		return fmt.Errorf("require Linux Landlock executable confinement: unsupported ABI %d", abi)
	}
	handledAccess := uint64(
		landlockAccessFSExecute | landlockAccessFSReadFile | landlockAccessFSReadDir,
	)
	rulesetAttribute := landlockRulesetAttr{HandledAccessFS: handledAccess}
	ruleset, _, errno := syscall.RawSyscall6(
		landlockCreateRuleset,
		uintptr(unsafe.Pointer(&rulesetAttribute)),
		unsafe.Sizeof(rulesetAttribute),
		0,
		0,
		0,
		0,
	)
	runtime.KeepAlive(&rulesetAttribute)
	if errno != 0 {
		return fmt.Errorf("create Landlock executable ruleset: %w", errno)
	}
	rulesetFD := int(ruleset)
	defer syscall.Close(rulesetFD)

	rules := make(map[string]uint64)
	for _, value := range executablePaths {
		rules[value] |= landlockAccessFSExecute | landlockAccessFSReadFile
	}
	for _, value := range readableFiles {
		rules[value] |= landlockAccessFSReadFile
	}
	for _, value := range readableDirectories {
		rules[value] |= landlockAccessFSReadFile | landlockAccessFSReadDir
	}
	for value, allowedAccess := range rules {
		pathFD, err := syscall.Open(value, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open Landlock executable path %s: %w", value, err)
		}
		pathAttribute := landlockPathBeneathAttr{
			AllowedAccess: allowedAccess,
			ParentFD:      int32(pathFD),
		}
		_, _, addErrno := syscall.RawSyscall6(
			landlockAddRule,
			uintptr(rulesetFD),
			landlockRulePathBeneath,
			uintptr(unsafe.Pointer(&pathAttribute)),
			0,
			0,
			0,
		)
		runtime.KeepAlive(&pathAttribute)
		_ = syscall.Close(pathFD)
		if addErrno != 0 {
			return fmt.Errorf("allow Landlock executable path %s: %w", value, addErrno)
		}
	}
	_, _, errno = syscall.Syscall6(
		syscall.SYS_PRCTL,
		prSetNoNewPrivs,
		1,
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("set no-new-privileges before Landlock: %w", errno)
	}
	_, _, errno = syscall.RawSyscall6(
		landlockRestrictSelf,
		uintptr(rulesetFD),
		0,
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("apply Landlock executable confinement: %w", errno)
	}
	return nil
}
