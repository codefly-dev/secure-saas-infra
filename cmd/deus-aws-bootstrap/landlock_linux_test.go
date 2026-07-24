//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestLandlockAllowsOnlyQualifiedExecutables(t *testing.T) {
	if os.Getenv("DEUS_LANDLOCK_TEST_HELPER") == "1" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		loader, libc := dynamicRuntimePaths(t)
		if err := restrictFileAccess(
			[]string{"/bin/true", loader},
			[]string{libc, "/dev/null"},
			nil,
		); err != nil {
			t.Fatalf("apply Landlock test ruleset: %v", err)
		}
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatalf("qualified executable was denied: %v", err)
		}
		if err := exec.Command("/bin/false").Run(); err == nil ||
			!strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("unqualified executable was not kernel-denied: %v", err)
		}
		if err := exec.Command(loader, "/bin/false").Run(); err == nil {
			t.Fatal("dynamic-loader bypass executed the denied binary")
		} else if exitError, ok := err.(*exec.ExitError); !ok || exitError.ExitCode() != 127 {
			t.Fatalf("dynamic-loader bypass was not denied while reading its target: %v", err)
		}
		if _, err := os.ReadFile("/etc/shadow"); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("unqualified readable file was not kernel-denied: %v", err)
		}
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestLandlockAllowsOnlyQualifiedExecutables$")
	command.Env = append(os.Environ(), "DEUS_LANDLOCK_TEST_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Landlock subprocess failed: %v\n%s", err, output)
	}
}

func dynamicRuntimePaths(t *testing.T) (string, string) {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return "/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/libc.so.6"
	case "arm64":
		return "/lib/ld-linux-aarch64.so.1", "/lib/aarch64-linux-gnu/libc.so.6"
	default:
		t.Fatalf("unsupported Landlock test architecture %s", runtime.GOARCH)
		return "", ""
	}
}
