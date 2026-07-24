//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	signerRuntimeAccount = "deus-signer-runtime"
	signingLockPath      = "/run/deus-bootstrap-signing.lock"
)

type signerSourceManifest struct {
	APIVersion     string `json:"apiVersion"`
	ReleaseTag     string `json:"releaseTag"`
	SourceRevision string `json:"sourceRevision"`
	Files          []struct {
		Path       string `json:"path"`
		Executable bool   `json:"executable"`
		SHA256     string `json:"sha256"`
	} `json:"files"`
	ManifestDigest string `json:"manifestDigest"`
}

type signerReviewSnapshotEntry struct {
	Path       string
	Type       string
	Size       int64
	Executable bool
	SHA256     string
	Target     string
}

func acquireSigningTransaction() (*os.File, error) {
	file, err := os.OpenFile(signingLockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open signing transaction lock: %w", err)
	}
	info, err := file.Stat()
	stat, ok := infoSyscallStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 {
		_ = file.Close()
		return nil, errors.New("signing transaction lock is not root-owned mode 0600")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another signing transaction is active")
	}
	return file, nil
}

func releaseSigningTransaction(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func requireDedicatedSignerIdentity(uid, gid int) error {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Errorf("read signer account: %w", err)
	}
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return fmt.Errorf("read signer shadow account: %w", err)
	}
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		return fmt.Errorf("read signer group inventory: %w", err)
	}
	if err := validateDedicatedSignerIdentity(passwd, shadow, group, uid, gid); err != nil {
		return err
	}
	return requireNoProcessesForUID(uid)
}

func validateDedicatedSignerIdentity(passwd, shadow, group []byte, uid, gid int) error {
	uidText := strconv.Itoa(uid)
	gidText := strconv.Itoa(gid)
	accounts := 0
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || (fields[0] != signerRuntimeAccount && fields[2] != uidText) {
			continue
		}
		accounts++
		if fields[0] != signerRuntimeAccount || fields[2] != uidText || fields[3] != gidText || fields[5] != "/nonexistent" ||
			(fields[6] != "/usr/sbin/nologin" && fields[6] != "/sbin/nologin") {
			return errors.New("signer UID must belong exclusively to the locked non-login deus-signer-runtime account")
		}
	}
	if accounts != 1 {
		return errors.New("signer UID/account mapping is not unique")
	}
	shadowEntries := 0
	for _, line := range strings.Split(string(shadow), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 || fields[0] != signerRuntimeAccount {
			continue
		}
		shadowEntries++
		if len(fields) != 9 || (!strings.HasPrefix(fields[1], "!") && !strings.HasPrefix(fields[1], "*")) {
			return errors.New("signer shadow account is not password-locked")
		}
	}
	if shadowEntries != 1 {
		return errors.New("signer shadow account is not unique")
	}
	primaryGroups := 0
	for _, line := range strings.Split(string(group), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			continue
		}
		members := strings.Split(fields[3], ",")
		for _, member := range members {
			if member == signerRuntimeAccount {
				return errors.New("signer account has a forbidden supplementary group")
			}
		}
		if fields[2] == gidText || fields[0] == signerRuntimeAccount {
			primaryGroups++
			if fields[0] != signerRuntimeAccount || fields[2] != gidText || fields[3] != "" {
				return errors.New("signer primary group is not exact and empty")
			}
		}
	}
	if primaryGroups != 1 {
		return errors.New("signer primary group mapping is not unique")
	}
	return nil
}

func requirePreparedSignerReviewTree(root, manifestPath string) error {
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read signer source manifest: %w", err)
	}
	manifest, err := parseSignerSourceManifest(contents)
	if err != nil {
		return err
	}
	return validatePreparedSignerReviewTree(root, manifest)
}

func parseSignerSourceManifest(contents []byte) (signerSourceManifest, error) {
	var manifest signerSourceManifest
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, fmt.Errorf("parse signer source manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return manifest, errors.New("signer source manifest has trailing content")
	}
	if manifest.APIVersion != "security.deus.dev/bootstrap-host-source-manifest/v1" ||
		!isSHA256(manifest.ManifestDigest) || len(manifest.Files) == 0 || len(manifest.Files) > 10_000 ||
		len(manifest.SourceRevision) != 40 || !strings.HasPrefix(manifest.ReleaseTag, "v") {
		return manifest, errors.New("signer source manifest envelope is malformed")
	}
	return manifest, nil
}

func validatePreparedSignerReviewTree(root string, manifest signerSourceManifest) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || filepath.Clean(resolvedRoot) != filepath.Clean(root) {
		return errors.New("signer review root must be a direct directory")
	}
	expected := make(map[string]struct {
		executable bool
		sha256     string
	}, len(manifest.Files))
	previous := ""
	for _, entry := range manifest.Files {
		if !safeSignerRelativePath(entry.Path) || !isSHA256(entry.SHA256) || entry.Path <= previous {
			return errors.New("signer source manifest file inventory is unsafe or unsorted")
		}
		expected[entry.Path] = struct {
			executable bool
			sha256     string
		}{entry.Executable, entry.SHA256}
		previous = entry.Path
	}
	generatedRoots := []string{
		"artifacts/bootstrap-pulumi-home",
		"artifacts/deus-aws-bootstrap",
		"dist-management-seed",
		"dist-management-seed-policy",
		"dist-management-seed-support",
		"node_modules",
	}
	for _, required := range generatedRoots {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(required)))
		if err != nil {
			return fmt.Errorf("signer review tree lacks required reconstructed path %s", required)
		}
		if required == "artifacts/deus-aws-bootstrap" {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
				return errors.New("signer review tree launcher is not a direct executable")
			}
		} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("signer reconstructed path is not a direct directory: %s", required)
		}
	}
	seen := make(map[string]bool, len(expected))
	if err := filepath.WalkDir(root, func(value string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, value)
		if err != nil || relative == "." {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(value)
		if err != nil {
			return err
		}
		if relative == ".git" || strings.HasPrefix(relative, ".git/") {
			if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return fmt.Errorf("signer Git metadata contains an unsafe object at %s", relative)
			}
			return nil
		}
		if wanted, ok := expected[relative]; ok {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || ((info.Mode().Perm()&0o111) != 0) != wanted.executable {
				return fmt.Errorf("signer tracked file type or mode changed at %s", relative)
			}
			digest, err := sha256File(value)
			if err != nil || digest != wanted.sha256 {
				return fmt.Errorf("signer tracked file bytes changed at %s", relative)
			}
			seen[relative] = true
			return nil
		}
		generatedRoot := matchingGeneratedRoot(relative, generatedRoots)
		if generatedRoot != "" {
			if info.Mode()&os.ModeSymlink != 0 {
				if generatedRoot != "node_modules" {
					return fmt.Errorf("signer generated path contains a forbidden symlink at %s", relative)
				}
				target, err := filepath.EvalSymlinks(value)
				if err != nil || !pathWithin(filepath.Join(root, "node_modules"), target) {
					return fmt.Errorf("signer dependency symlink escapes the exact root at %s", relative)
				}
				return nil
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return fmt.Errorf("signer generated path has an unsafe type at %s", relative)
			}
			return nil
		}
		if info.IsDir() && (isExpectedAncestor(relative, expected) || isRootAncestor(relative, generatedRoots)) {
			return nil
		}
		return fmt.Errorf("signer review tree contains unexpected ignored path %s", relative)
	}); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("signer review tree does not contain every manifested source file")
	}
	return nil
}

func safeSignerRelativePath(value string) bool {
	return value != "" && len(value) <= 1024 && !filepath.IsAbs(value) && filepath.IsLocal(value) &&
		!strings.Contains(value, "\\") && filepath.ToSlash(filepath.Clean(value)) == value
}

func matchingGeneratedRoot(value string, roots []string) string {
	for _, root := range roots {
		if value == root || strings.HasPrefix(value, root+"/") {
			return root
		}
	}
	return ""
}

func isExpectedAncestor(value string, expected map[string]struct {
	executable bool
	sha256     string
}) bool {
	for path := range expected {
		if strings.HasPrefix(path, value+"/") {
			return true
		}
	}
	return false
}

func isRootAncestor(value string, roots []string) bool {
	for _, root := range roots {
		if strings.HasPrefix(root, value+"/") {
			return true
		}
	}
	return false
}

func pathWithin(root, value string) bool {
	relative, err := filepath.Rel(root, value)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func replaceSignerReviewTreeWithSnapshot(root string, manifest signerSourceManifest, sourceUID, sourceGID int) error {
	return replaceSignerReviewTreeWithSnapshotAs(root, manifest, sourceUID, sourceGID, 0, 0)
}

func replaceSignerReviewTreeWithSnapshotAs(root string, manifest signerSourceManifest, sourceUID, sourceGID, sealedUID, sealedGID int) error {
	if err := validatePreparedSignerReviewTree(root, manifest); err != nil {
		return err
	}
	inventory, err := captureSignerReviewSnapshot(root, sourceUID, sourceGID)
	if err != nil {
		return err
	}
	staging := fmt.Sprintf("%s.signing-seal.%d", root, os.Getpid())
	unsealed := fmt.Sprintf("%s.signing-unsealed.%d", root, os.Getpid())
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("remove stale signer sealing root: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := copySealedTree(root, staging, sourceUID, sealedGID); err != nil {
		return err
	}
	if err := validateSignerReviewSnapshot(staging, inventory, sealedUID, sealedGID); err != nil {
		return fmt.Errorf("fresh signer snapshot differs from prepared review tree: %w", err)
	}
	if err := verifyFrozenSignerReviewTree(staging, sealedUID, sealedGID); err != nil {
		return err
	}
	if err := os.Rename(root, unsealed); err != nil {
		return fmt.Errorf("retire signer preparation tree: %w", err)
	}
	if err := os.Rename(staging, root); err != nil {
		if restoreErr := os.Rename(unsealed, root); restoreErr != nil {
			return fmt.Errorf("publish signer snapshot: %w (restore also failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("publish signer snapshot: %w", err)
	}
	if err := os.RemoveAll(unsealed); err != nil {
		return fmt.Errorf("remove consumed signer preparation tree: %w", err)
	}
	parent, err := os.Open(filepath.Dir(root))
	if err != nil {
		return fmt.Errorf("open signer snapshot parent: %w", err)
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("persist fresh signer snapshot publication")
	}
	return nil
}

func captureSignerReviewSnapshot(root string, expectedUID, expectedGID int) ([]signerReviewSnapshotEntry, error) {
	entries := make([]signerReviewSnapshotEntry, 0)
	var total int64
	if err := filepath.WalkDir(root, func(value string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(value)
		if err != nil {
			return err
		}
		stat, ok := infoSyscallStat(info)
		if !ok || int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID {
			return fmt.Errorf("signer snapshot path has unexpected ownership: %s", value)
		}
		if value == root {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("signer snapshot root is not a direct directory")
			}
			return nil
		}
		if len(entries) >= sealMaximumEntries {
			return errors.New("signer snapshot exceeds the filesystem entry budget")
		}
		relative, err := filepath.Rel(root, value)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !safeSignerRelativePath(relative) {
			return fmt.Errorf("signer snapshot path is unsafe: %s", relative)
		}
		snapshot := signerReviewSnapshotEntry{Path: relative}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			snapshot.Type = "symlink"
			snapshot.Target, err = os.Readlink(value)
			if err != nil {
				return err
			}
		case info.IsDir():
			snapshot.Type = "directory"
		case info.Mode().IsRegular():
			if info.Size() < 0 || info.Size() > sealMaximumFileSize || total > sealMaximumTreeSize-info.Size() {
				return fmt.Errorf("signer snapshot file budget exceeded at %s", relative)
			}
			total += info.Size()
			snapshot.Type = "file"
			snapshot.Size = info.Size()
			snapshot.Executable = info.Mode().Perm()&0o111 != 0
			snapshot.SHA256, err = sha256File(value)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("signer snapshot contains unsupported path %s", relative)
		}
		entries = append(entries, snapshot)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	return entries, nil
}

func validateSignerReviewSnapshot(root string, expected []signerReviewSnapshotEntry, ownerUID, ownerGID int) error {
	actual, err := captureSignerReviewSnapshot(root, ownerUID, ownerGID)
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return errors.New("signer snapshot entry count changed")
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return fmt.Errorf("signer snapshot entry changed at %s", expected[index].Path)
		}
	}
	return nil
}

func freezeSignerReviewTree(root string) error {
	return freezeSignerReviewTreeAs(root, 0, 0)
}

func freezeSignerReviewTreeAs(root string, ownerUID, ownerGID int) error {
	if err := filepath.WalkDir(root, func(value string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(value)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := infoSyscallStat(info)
			if !ok {
				return errors.New("signer review symlink ownership is unavailable")
			}
			if int(stat.Uid) != ownerUID || int(stat.Gid) != ownerGID {
				return os.Lchown(value, ownerUID, ownerGID)
			}
			return nil
		}
		stat, ok := infoSyscallStat(info)
		if !ok {
			return errors.New("signer review path ownership is unavailable")
		}
		if int(stat.Uid) != ownerUID || int(stat.Gid) != ownerGID {
			if err := os.Chown(value, ownerUID, ownerGID); err != nil {
				return err
			}
		}
		mode := os.FileMode(0o444)
		if info.IsDir() || info.Mode().Perm()&0o111 != 0 {
			mode = 0o555
		}
		return os.Chmod(value, mode)
	}); err != nil {
		return fmt.Errorf("freeze signer review tree: %w", err)
	}
	return verifyFrozenSignerReviewTree(root, ownerUID, ownerGID)
}

func verifyFrozenSignerReviewTree(root string, ownerUID, ownerGID int) error {
	paths := make([]string, 0)
	if err := filepath.WalkDir(root, func(value string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		paths = append(paths, value)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(paths)
	for _, value := range paths {
		info, err := os.Lstat(value)
		stat, ok := infoSyscallStat(info)
		if err != nil || !ok || int(stat.Uid) != ownerUID || int(stat.Gid) != ownerGID {
			return fmt.Errorf("signer review path is not root-frozen: %s", value)
		}
		// Linux symlink permission bits are always 0777 and are not access
		// controls. Their owner and contained target were validated before the
		// freeze; require write bits to be absent only on real files/directories.
		if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o222 != 0 {
			return fmt.Errorf("signer review path remains writable: %s", value)
		}
	}
	return nil
}
