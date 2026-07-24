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
	"path/filepath"
	"sort"
	"strings"
)

type managementSeedSealScope struct {
	APIVersion  string   `json:"apiVersion"`
	SourceFiles []string `json:"sourceFiles"`
}

type sealInventoryBudget struct {
	maximumEntries  int
	maximumFileSize int64
	maximumTreeSize int64
}

type bootstrapSealInventory struct {
	APIVersion      string                        `json:"apiVersion"`
	EntryCount      int                           `json:"entryCount"`
	TotalFileBytes  int64                         `json:"totalFileBytes"`
	MaximumFileSize int64                         `json:"maximumFileSize"`
	Entries         []bootstrapSealInventoryEntry `json:"entries"`
	DocumentSHA256  string                        `json:"-"`
	CandidateSHA256 string                        `json:"-"`
}

type bootstrapSealInventoryEntry struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size,omitempty"`
	Executable bool   `json:"executable,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Target     string `json:"target,omitempty"`
}

var sealedGeneratedRoots = []string{
	"artifacts/bootstrap-pulumi-home/plugins/resource-aws-v7.27.0",
	"dist-management-seed",
	"dist-management-seed-policy",
	"node_modules",
}

var sealedGeneratedFiles = []string{
	"Pulumi.management.yaml",
	"artifacts/bootstrap-candidate.json",
	"artifacts/bootstrap-seal-inventory.json",
	"artifacts/contract-schema-validation.json",
	"artifacts/deus-aws-bootstrap",
	"artifacts/local-gate-evidence.json",
	"artifacts/management-seed-access-bundle.json",
	"artifacts/management-seed-access.template.json",
	"artifacts/secure-saas-infra.spdx.json",
	"artifacts/security-contract-evidence.json",
	"onboarding.local.json",
}

var sealedEmptyDirectories = []string{
	"artifacts/pulumi-plans",
	"artifacts/runtime-output",
}

func prepareExecutionTreeForSeal(root, manifestPath, candidatePath string, qualificationUID int) (func(string, int) error, error) {
	if err := requireNoProcessesForUID(qualificationUID); err != nil {
		return nil, fmt.Errorf("qualification identity must have zero processes before sealing: %w", err)
	}
	manifestContents, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read installed source manifest before sealing: %w", err)
	}
	manifest, err := parseSignerSourceManifest(manifestContents)
	if err != nil {
		return nil, err
	}
	scope, err := readManagementSeedSealScope(filepath.Join(root, "security", "management-seed-qualification-scope.json"))
	if err != nil {
		return nil, err
	}
	generated, err := readBootstrapSealInventory(root, candidatePath)
	if err != nil {
		return nil, err
	}
	sourceSet := make(map[string]bool, len(scope.SourceFiles))
	for _, value := range scope.SourceFiles {
		sourceSet[value] = true
	}
	if err := pruneExecutionTree(root, manifest, sourceSet); err != nil {
		return nil, err
	}
	if err := validateExecutionSealInventory(root, manifest, scope, generated, qualificationUID); err != nil {
		return nil, err
	}
	if err := requireNoProcessesForUID(qualificationUID); err != nil {
		return nil, fmt.Errorf("qualification identity restarted during seal capture: %w", err)
	}
	return func(sealedRoot string, expectedUID int) error {
		return validateExecutionSealInventory(sealedRoot, manifest, scope, generated, expectedUID)
	}, nil
}

func readBootstrapSealInventory(root, candidatePath string) (bootstrapSealInventory, error) {
	var inventory bootstrapSealInventory
	candidateContents, err := os.ReadFile(candidatePath)
	if err != nil {
		return inventory, fmt.Errorf("read signed candidate seal binding: %w", err)
	}
	var envelope struct {
		SealInventory struct {
			Path            string `json:"path"`
			SHA256          string `json:"sha256"`
			EntryCount      int    `json:"entryCount"`
			TotalFileBytes  int64  `json:"totalFileBytes"`
			MaximumFileSize int64  `json:"maximumFileSize"`
		} `json:"sealInventory"`
	}
	if err := json.Unmarshal(candidateContents, &envelope); err != nil {
		return inventory, errors.New("signed candidate seal binding is malformed")
	}
	binding := envelope.SealInventory
	if binding.Path != "artifacts/bootstrap-seal-inventory.json" || len(binding.SHA256) != 64 || !lowerHex(binding.SHA256) {
		return inventory, errors.New("signed candidate seal inventory locator is invalid")
	}
	inventoryPath := filepath.Join(root, filepath.FromSlash(binding.Path))
	digest, err := sha256File(inventoryPath)
	if err != nil || digest != binding.SHA256 {
		return inventory, errors.New("signed candidate seal inventory digest differs")
	}
	contents, err := os.ReadFile(inventoryPath)
	if err != nil {
		return inventory, fmt.Errorf("read bootstrap seal inventory: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return inventory, fmt.Errorf("parse bootstrap seal inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return inventory, errors.New("bootstrap seal inventory has trailing content")
	}
	if inventory.APIVersion != "security.deus.dev/bootstrap-seal-inventory/v1" || inventory.EntryCount != len(inventory.Entries) || inventory.EntryCount != binding.EntryCount || inventory.TotalFileBytes != binding.TotalFileBytes || inventory.MaximumFileSize != binding.MaximumFileSize || inventory.EntryCount <= 0 || inventory.EntryCount > sealMaximumEntries || inventory.TotalFileBytes <= 0 || inventory.TotalFileBytes > sealMaximumTreeSize || inventory.MaximumFileSize <= 0 || inventory.MaximumFileSize > sealMaximumFileSize {
		return inventory, errors.New("bootstrap seal inventory summary is invalid")
	}
	rootKinds := make(map[string]string, len(sealedGeneratedRoots))
	for _, value := range sealedGeneratedRoots {
		rootKinds[value] = "directory"
	}
	fileSet := make(map[string]bool, len(sealedGeneratedFiles))
	for _, value := range sealedGeneratedFiles {
		fileSet[value] = true
	}
	previous := ""
	seen := make(map[string]bool, len(inventory.Entries))
	var total int64
	var maximum int64
	for _, entry := range inventory.Entries {
		if !safeSignerRelativePath(entry.Path) || entry.Path <= previous || seen[entry.Path] || entry.Path == binding.Path || entry.Path == "artifacts/bootstrap-candidate.json" {
			return inventory, errors.New("bootstrap seal inventory path order or identity is invalid")
		}
		seen[entry.Path] = true
		previous = entry.Path
		generatedRoot := matchingGeneratedRoot(entry.Path, sealedGeneratedRoots)
		if generatedRoot == "" && !fileSet[entry.Path] {
			return inventory, fmt.Errorf("bootstrap seal inventory contains an unapproved path %s", entry.Path)
		}
		switch entry.Type {
		case "directory":
			if entry.Size != 0 || entry.SHA256 != "" || entry.Target != "" || entry.Executable {
				return inventory, fmt.Errorf("bootstrap seal directory metadata is invalid at %s", entry.Path)
			}
		case "file":
			if entry.Size < 0 || entry.Size > sealMaximumFileSize || len(entry.SHA256) != 64 || !lowerHex(entry.SHA256) || entry.Target != "" {
				return inventory, fmt.Errorf("bootstrap seal file metadata is invalid at %s", entry.Path)
			}
			total += entry.Size
			if entry.Size > maximum {
				maximum = entry.Size
			}
		case "symlink":
			if generatedRoot != "node_modules" || entry.Target == "" || filepath.IsAbs(entry.Target) || entry.Size != 0 || entry.SHA256 != "" || entry.Executable {
				return inventory, fmt.Errorf("bootstrap seal symlink metadata is invalid at %s", entry.Path)
			}
		default:
			return inventory, fmt.Errorf("bootstrap seal entry type is invalid at %s", entry.Path)
		}
	}
	for value, kind := range rootKinds {
		entryFound := false
		for _, entry := range inventory.Entries {
			if entry.Path == value && entry.Type == kind {
				entryFound = true
				break
			}
		}
		if !entryFound {
			return inventory, fmt.Errorf("bootstrap seal inventory lacks generated root %s", value)
		}
	}
	for _, value := range sealedGeneratedFiles {
		if value == "artifacts/bootstrap-candidate.json" || value == binding.Path {
			continue
		}
		entry, ok := findBootstrapSealEntry(inventory.Entries, value)
		if !ok || entry.Type != "file" {
			return inventory, fmt.Errorf("bootstrap seal inventory lacks generated file %s", value)
		}
	}
	if total != inventory.TotalFileBytes || maximum != inventory.MaximumFileSize {
		return inventory, errors.New("bootstrap seal inventory byte summary differs from its entries")
	}
	inventory.DocumentSHA256 = binding.SHA256
	inventory.CandidateSHA256 = fmt.Sprintf("%x", sha256.Sum256(candidateContents))
	return inventory, nil
}

func findBootstrapSealEntry(entries []bootstrapSealInventoryEntry, wanted string) (bootstrapSealInventoryEntry, bool) {
	index := sort.Search(len(entries), func(index int) bool { return entries[index].Path >= wanted })
	if index >= len(entries) || entries[index].Path != wanted {
		return bootstrapSealInventoryEntry{}, false
	}
	return entries[index], true
}

func readManagementSeedSealScope(value string) (managementSeedSealScope, error) {
	contents, err := os.ReadFile(value)
	if err != nil {
		return managementSeedSealScope{}, fmt.Errorf("read management-seed seal scope: %w", err)
	}
	var scope managementSeedSealScope
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&scope); err != nil {
		return scope, fmt.Errorf("parse management-seed seal scope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return scope, errors.New("management-seed seal scope has trailing content")
	}
	if scope.APIVersion != "security.deus.dev/management-seed-qualification-scope/v1" || len(scope.SourceFiles) == 0 || len(scope.SourceFiles) > 2_000 {
		return scope, errors.New("management-seed seal source inventory is malformed")
	}
	previous := ""
	seen := make(map[string]bool, len(scope.SourceFiles))
	for _, entry := range scope.SourceFiles {
		if !safeSignerRelativePath(entry) || entry <= previous || seen[entry] {
			return scope, errors.New("management-seed seal source inventory is unsafe, duplicate, or unsorted")
		}
		seen[entry] = true
		previous = entry
	}
	return scope, nil
}

func pruneExecutionTree(root string, manifest signerSourceManifest, retained map[string]bool) error {
	for _, forbidden := range []string{
		".git",
		"dist-management-seed-support",
		"dist-management-seed-test",
		"artifacts/bootstrap-candidate.payload",
		"artifacts/bootstrap-candidate.unsigned.json",
	} {
		if err := os.RemoveAll(filepath.Join(root, filepath.FromSlash(forbidden))); err != nil {
			return fmt.Errorf("remove qualification-only path %s: %w", forbidden, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "artifacts", "bootstrap-signing-review-bundle.json")); err == nil {
		return errors.New("confidential signing review bundle remains before sealing")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect confidential signing review bundle: %w", err)
	}
	for _, entry := range manifest.Files {
		if retained[entry.Path] {
			continue
		}
		value := filepath.Join(root, filepath.FromSlash(entry.Path))
		if err := os.Remove(value); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove out-of-scope tracked source %s: %w", entry.Path, err)
		}
	}
	return removeUnneededEmptyDirectories(root)
}

func removeUnneededEmptyDirectories(root string) error {
	keep := make(map[string]bool, len(sealedEmptyDirectories))
	for _, value := range sealedEmptyDirectories {
		keep[value] = true
	}
	directories := make([]string, 0)
	if err := filepath.WalkDir(root, func(value string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && value != root {
			directories = append(directories, value)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(left, right int) bool { return len(directories[left]) > len(directories[right]) })
	for _, value := range directories {
		relative, err := filepath.Rel(root, value)
		if err != nil || keep[filepath.ToSlash(relative)] {
			continue
		}
		entries, err := os.ReadDir(value)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			if err := os.Remove(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateExecutionSealInventory(root string, manifest signerSourceManifest, scope managementSeedSealScope, generated bootstrapSealInventory, expectedUID int) error {
	return validateExecutionSealInventoryWithBudget(root, manifest, scope, generated, expectedUID, sealInventoryBudget{
		maximumEntries:  sealMaximumEntries,
		maximumFileSize: sealMaximumFileSize,
		maximumTreeSize: sealMaximumTreeSize,
	})
}

func validateExecutionSealInventoryWithBudget(root string, manifest signerSourceManifest, scope managementSeedSealScope, generated bootstrapSealInventory, expectedUID int, budget sealInventoryBudget) error {
	if budget.maximumEntries <= 0 || budget.maximumFileSize <= 0 || budget.maximumTreeSize <= 0 {
		return errors.New("seal inventory budget is invalid")
	}
	manifested := make(map[string]struct {
		executable bool
		sha256     string
	}, len(manifest.Files))
	for _, entry := range manifest.Files {
		manifested[entry.Path] = struct {
			executable bool
			sha256     string
		}{entry.Executable, entry.SHA256}
	}
	exact := make(map[string]string, len(scope.SourceFiles)+len(sealedGeneratedFiles))
	for _, value := range scope.SourceFiles {
		exact[value] = "source"
		if _, ok := manifested[value]; !ok {
			return fmt.Errorf("governed source %s is absent from the installed release manifest", value)
		}
	}
	for _, value := range sealedGeneratedFiles {
		if _, duplicate := exact[value]; duplicate {
			return fmt.Errorf("duplicate exact seal path %s", value)
		}
		exact[value] = "generated"
	}
	generatedEntries := make(map[string]bootstrapSealInventoryEntry, len(generated.Entries))
	for _, entry := range generated.Entries {
		if _, duplicate := exact[entry.Path]; duplicate {
			if exact[entry.Path] != "generated" {
				return fmt.Errorf("generated seal entry overlaps governed source at %s", entry.Path)
			}
		} else {
			exact[entry.Path] = "generated-inventory"
		}
		generatedEntries[entry.Path] = entry
	}
	requiredEmpty := make(map[string]bool, len(sealedEmptyDirectories))
	for _, value := range sealedEmptyDirectories {
		requiredEmpty[value] = false
	}
	seenExact := make(map[string]bool, len(exact))
	entries := 0
	var totalBytes int64
	if err := filepath.WalkDir(root, func(value string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if value == root {
			return validateSealOwner(value, expectedUID, true)
		}
		entries++
		if entries > budget.maximumEntries {
			return fmt.Errorf("seal inventory exceeds %d filesystem entries", budget.maximumEntries)
		}
		relative, err := filepath.Rel(root, value)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !safeSignerRelativePath(relative) {
			return fmt.Errorf("seal inventory contains unsafe path %s", relative)
		}
		info, err := os.Lstat(value)
		if err != nil {
			return err
		}
		_, exactPath := exact[relative]
		_, emptyPath := requiredEmpty[relative]
		allowedDirectory := info.IsDir() && (isSealAncestor(relative, exact, sealedEmptyDirectories) || emptyPath)
		if !exactPath && !allowedDirectory && !emptyPath {
			return fmt.Errorf("seal inventory contains unexpected path %s", relative)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			wanted, ok := generatedEntries[relative]
			if !ok || wanted.Type != "symlink" || matchingGeneratedRoot(relative, sealedGeneratedRoots) != "node_modules" {
				return fmt.Errorf("seal inventory contains forbidden symlink %s", relative)
			}
			targetValue, readErr := os.Readlink(value)
			target, err := filepath.EvalSymlinks(value)
			if readErr != nil || targetValue != wanted.Target || err != nil || !pathWithin(filepath.Join(root, "node_modules"), target) {
				return fmt.Errorf("dependency symlink escapes the sealed dependency root at %s", relative)
			}
			seenExact[relative] = true
			return validateSealOwner(value, expectedUID, false)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("seal inventory contains unsupported filesystem type at %s", relative)
		}
		if err := validateSealOwner(value, expectedUID, info.IsDir()); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || info.Size() > budget.maximumFileSize {
				return fmt.Errorf("seal file %s exceeds the per-file size budget", relative)
			}
			totalBytes += info.Size()
			if totalBytes > budget.maximumTreeSize {
				return fmt.Errorf("seal inventory exceeds the total byte budget")
			}
		}
		if wanted, ok := generatedEntries[relative]; ok {
			switch wanted.Type {
			case "directory":
				if !info.IsDir() {
					return fmt.Errorf("generated seal directory changed type at %s", relative)
				}
			case "file":
				if !info.Mode().IsRegular() || info.Size() != wanted.Size || ((info.Mode().Perm()&0o111) != 0) != wanted.Executable {
					return fmt.Errorf("generated seal file metadata changed at %s", relative)
				}
				digest, err := sha256File(value)
				if err != nil || digest != wanted.SHA256 {
					return fmt.Errorf("generated seal file digest changed at %s", relative)
				}
			default:
				return fmt.Errorf("generated seal entry changed type at %s", relative)
			}
			seenExact[relative] = true
		} else if exactPath {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("exact seal path is not a regular file: %s", relative)
			}
			seenExact[relative] = true
			if exact[relative] == "source" {
				wanted := manifested[relative]
				digest, err := sha256File(value)
				if err != nil || digest != wanted.sha256 || ((info.Mode().Perm()&0o111) != 0) != wanted.executable {
					return fmt.Errorf("governed source differs from the installed release manifest at %s", relative)
				}
			} else if relative == "artifacts/bootstrap-candidate.json" {
				digest, err := sha256File(value)
				if err != nil || digest != generated.CandidateSHA256 {
					return errors.New("signed bootstrap candidate changed during seal capture")
				}
			} else if relative == "artifacts/bootstrap-seal-inventory.json" {
				digest, err := sha256File(value)
				if err != nil || digest != generated.DocumentSHA256 {
					return errors.New("bootstrap seal inventory document changed during capture")
				}
			}
		}
		if emptyPath {
			if !info.IsDir() {
				return fmt.Errorf("runtime output path is not a directory: %s", relative)
			}
			children, err := os.ReadDir(value)
			if err != nil || len(children) != 0 {
				return fmt.Errorf("runtime output path must be empty before sealing: %s", relative)
			}
			requiredEmpty[relative] = true
		}
		return nil
	}); err != nil {
		return err
	}
	if len(seenExact) != len(exact) {
		return errors.New("seal inventory does not contain every exact source and generated file")
	}
	for value, seen := range requiredEmpty {
		if !seen {
			return fmt.Errorf("seal inventory lacks required empty output directory %s", value)
		}
	}
	return nil
}

func validateSealOwner(value string, qualificationUID int, directory bool) error {
	info, err := os.Lstat(value)
	if err != nil {
		return fmt.Errorf("inspect seal path ownership: %w", err)
	}
	stat, ok := infoSyscallStat(info)
	if !ok || int(stat.Uid) != qualificationUID {
		return fmt.Errorf("seal path is not owned by the qualification identity: %s", value)
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("seal path is not a directory: %s", value)
	}
	return nil
}

func isSealAncestor(value string, exact map[string]string, empty []string) bool {
	for candidate := range exact {
		if strings.HasPrefix(candidate, value+"/") {
			return true
		}
	}
	for _, candidate := range empty {
		if strings.HasPrefix(candidate, value+"/") {
			return true
		}
	}
	return false
}
