//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const planReviewRoot = "/var/lib/deus-bootstrap-plan-reviews"

var (
	planFilePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+\.plan\.json$`)
	stackPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

type planReviewManifest struct {
	APIVersion               string `json:"apiVersion"`
	Kind                     string `json:"kind"`
	GeneratedAt              string `json:"generatedAt"`
	SourceRevision           string `json:"sourceRevision"`
	ManagementAccountID      string `json:"managementAccountId"`
	PulumiOrganization       string `json:"pulumiOrganization"`
	PulumiProject            string `json:"pulumiProject"`
	BootstrapCandidateDigest string `json:"bootstrapCandidateDigest"`
	Plans                    []struct {
		Stack    string `json:"stack"`
		PlanFile string `json:"planFile"`
		SHA256   string `json:"sha256"`
	} `json:"plans"`
}

func exportPlanReview(args []string) error {
	if os.Geteuid() != 0 || len(args) != 2 || args[0] != "--manifest-digest" || !isSHA256(args[1]) {
		return errors.New("export-plan-review requires root and --manifest-digest <sha256>")
	}
	if err := requireInstalledLauncher(); err != nil {
		return err
	}
	runtimeUID, runtimeGID, err := sealedRuntimeIdentity()
	if err != nil {
		return err
	}
	if err := requireNoProcessesForUID(runtimeUID); err != nil {
		return err
	}
	planDirectory := filepath.Join(executionRoot, "artifacts", "pulumi-plans")
	manifestPath := filepath.Join(planDirectory, "manifest.json")
	manifestBytes, err := readRuntimePlanFile(manifestPath, runtimeUID, runtimeGID)
	if err != nil {
		return err
	}
	manifest, err := parsePlanReviewManifest(manifestBytes, args[1])
	if err != nil {
		return err
	}
	files := map[string][]byte{"manifest.json": manifestBytes}
	for _, plan := range manifest.Plans {
		contents, err := readRuntimePlanFile(filepath.Join(planDirectory, plan.PlanFile), runtimeUID, runtimeGID)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(contents)) != plan.SHA256 {
			return fmt.Errorf("runtime plan %s differs from its manifest", plan.PlanFile)
		}
		files[plan.PlanFile] = contents
	}
	operatorGroup, err := user.LookupGroup(runtimeOperatorGroup)
	if err != nil {
		return fmt.Errorf("lookup plan review operator group: %w", err)
	}
	operatorGID, err := strconv.Atoi(operatorGroup.Gid)
	if err != nil || operatorGID <= 0 {
		return errors.New("plan review operator group ID is invalid")
	}
	return publishPlanReview(args[1], operatorGID, files)
}

func requireFrozenPlanReview(digest string) error {
	if !isSHA256(digest) {
		return errors.New("frozen plan review digest is invalid")
	}
	operatorGroup, err := user.LookupGroup(runtimeOperatorGroup)
	if err != nil {
		return fmt.Errorf("lookup frozen plan review operator group: %w", err)
	}
	operatorGID, err := strconv.Atoi(operatorGroup.Gid)
	if err != nil || operatorGID <= 0 {
		return errors.New("frozen plan review operator group ID is invalid")
	}
	return validateFrozenPlanReview(filepath.Join(planReviewRoot, digest), digest, 0, operatorGID)
}

func validateFrozenPlanReview(destination, digest string, ownerUID, operatorGID int) error {
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o550 {
		return errors.New("required root-frozen plan review directory is unavailable or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != ownerUID || int(stat.Gid) != operatorGID {
		return errors.New("root-frozen plan review directory has an unexpected owner")
	}
	manifestBytes, err := readFrozenPlanReviewFile(filepath.Join(destination, "manifest.json"), ownerUID, operatorGID)
	if err != nil {
		return err
	}
	manifest, err := parsePlanReviewManifest(manifestBytes, digest)
	if err != nil {
		return err
	}
	expected := map[string]bool{"manifest.json": true}
	for _, plan := range manifest.Plans {
		contents, err := readFrozenPlanReviewFile(filepath.Join(destination, plan.PlanFile), ownerUID, operatorGID)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(contents)) != plan.SHA256 {
			return fmt.Errorf("frozen plan review %s differs from its manifest", plan.PlanFile)
		}
		expected[plan.PlanFile] = true
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != len(expected) {
		return errors.New("frozen plan review file inventory is not exact")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return errors.New("frozen plan review contains an unexpected file")
		}
	}
	return nil
}

func readFrozenPlanReviewFile(value string, ownerUID, operatorGID int) ([]byte, error) {
	file, err := os.OpenFile(value, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open frozen plan review file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o440 || info.Size() <= 0 || info.Size() > 100*1024*1024 {
		return nil, errors.New("frozen plan review file is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != ownerUID || int(stat.Gid) != operatorGID {
		return nil, errors.New("frozen plan review file has an unexpected owner")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 100*1024*1024+1))
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, errors.New("frozen plan review file changed or is unreadable")
	}
	return contents, nil
}

func requireNoProcessesForUID(uid int) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("inventory runtime processes before plan export: %w", err)
	}
	wanted := strconv.Itoa(uid)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("inspect protected UID process %s: %w", entry.Name(), err)
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
				if len(fields) == 4 && (fields[0] == wanted || fields[1] == wanted || fields[2] == wanted || fields[3] == wanted) {
					return fmt.Errorf("process %s remains active for protected UID %d", entry.Name(), uid)
				}
			}
		}
	}
	return nil
}

func sealedRuntimeIdentity() (int, int, error) {
	if err := requireRootOwnedRegularFile(runtimeIdentityPath, false); err != nil {
		return 0, 0, err
	}
	contents, err := os.ReadFile(runtimeIdentityPath)
	if err != nil {
		return 0, 0, err
	}
	parts := strings.Split(strings.TrimSuffix(string(contents), "\n"), ":")
	if len(parts) != 2 || !strings.HasSuffix(string(contents), "\n") {
		return 0, 0, errors.New("sealed runtime identity is malformed")
	}
	uid, err := parseIdentity(parts[0], "runtime UID")
	if err != nil {
		return 0, 0, err
	}
	gid, err := parseIdentity(parts[1], "runtime GID")
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func readRuntimePlanFile(value string, uid, gid int) ([]byte, error) {
	file, err := os.OpenFile(value, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("runtime plan input %s is not a protected direct regular file", value)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("runtime plan input %s is not a protected direct regular file", value)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return nil, fmt.Errorf("runtime plan input %s has an unexpected owner", value)
	}
	if info.Size() <= 0 || info.Size() > 100*1024*1024 {
		return nil, fmt.Errorf("runtime plan input %s is empty, excessive, or unreadable", value)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 100*1024*1024+1))
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, fmt.Errorf("runtime plan input %s changed or is unreadable", value)
	}
	return contents, nil
}

func parsePlanReviewManifest(contents []byte, expectedDigest string) (planReviewManifest, error) {
	if fmt.Sprintf("%x", sha256.Sum256(contents)) != expectedDigest {
		return planReviewManifest{}, errors.New("plan manifest does not match the operator-confirmed digest")
	}
	var manifest planReviewManifest
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return planReviewManifest{}, fmt.Errorf("parse plan review manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return planReviewManifest{}, errors.New("plan review manifest has trailing content")
	}
	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err != nil {
		return planReviewManifest{}, errors.New("plan review manifest timestamp is malformed")
	}
	if manifest.APIVersion != "security.deus.dev/pulumi-plan-manifest/v1alpha1" ||
		manifest.Kind != "PulumiPlanManifest" ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(manifest.SourceRevision) ||
		!regexp.MustCompile(`^[0-9]{12}$`).MatchString(manifest.ManagementAccountID) ||
		!stackPattern.MatchString(manifest.PulumiOrganization) ||
		!stackPattern.MatchString(manifest.PulumiProject) ||
		!isSHA256(manifest.BootstrapCandidateDigest) || len(manifest.Plans) == 0 {
		return planReviewManifest{}, errors.New("plan review manifest envelope is malformed")
	}
	seen := make(map[string]bool)
	previous := ""
	for _, plan := range manifest.Plans {
		if !stackPattern.MatchString(plan.Stack) || !planFilePattern.MatchString(plan.PlanFile) ||
			plan.PlanFile != plan.Stack+".plan.json" || !isSHA256(plan.SHA256) ||
			seen[plan.Stack] || plan.Stack <= previous {
			return planReviewManifest{}, errors.New("plan review manifest inventory is not exact and sorted")
		}
		seen[plan.Stack] = true
		previous = plan.Stack
	}
	return manifest, nil
}

func publishPlanReview(digest string, gid int, files map[string][]byte) error {
	if err := os.MkdirAll(planReviewRoot, 0o550); err != nil {
		return fmt.Errorf("create plan review root: %w", err)
	}
	if err := requireRootOwnedDirectory(planReviewRoot); err != nil {
		return err
	}
	if err := os.Chown(planReviewRoot, 0, gid); err != nil {
		return fmt.Errorf("own plan review root: %w", err)
	}
	if err := os.Chmod(planReviewRoot, 0o550); err != nil {
		return fmt.Errorf("protect plan review root: %w", err)
	}
	destination := filepath.Join(planReviewRoot, digest)
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("content-addressed plan review already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.MkdirTemp(planReviewRoot, ".plan-review-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chown(temporary, 0, gid); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		output := filepath.Join(temporary, name)
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
		if err != nil {
			return err
		}
		if _, err := file.Write(files[name]); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Chown(output, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(output, 0o440); err != nil {
			return err
		}
	}
	if err := os.Chmod(temporary, 0o550); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return nil
}
