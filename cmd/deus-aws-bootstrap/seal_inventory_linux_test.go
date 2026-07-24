//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func TestExecutionSealInventoryIsExactAndBudgeted(t *testing.T) {
	root, manifest, scope, generated := validSealInventoryFixture(t)
	if err := validateExecutionSealInventory(root, manifest, scope, generated, os.Getuid()); err != nil {
		t.Fatalf("exact seal inventory was rejected: %v", err)
	}

	for name, mutate := range map[string]func(string){
		"unexpected ignored file": func(root string) {
			writeSealFixtureFile(t, root, "ignored-attacker.js", "attacker")
		},
		"unmanifested dependency file": func(root string) {
			writeSealFixtureFile(t, root, "node_modules/attacker.js", "attacker")
		},
		"changed generated file": func(root string) {
			writeSealFixtureFile(t, root, "dist-management-seed/.inventory", "changed")
		},
		"special file": func(root string) {
			if err := syscall.Mkfifo(filepath.Join(root, "node_modules", "attacker.fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"external symlink": func(root string) {
			if err := os.Symlink("/etc/passwd", filepath.Join(root, "node_modules", "escape")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			hostile, hostileManifest, hostileScope, hostileGenerated := validSealInventoryFixture(t)
			mutate(hostile)
			if err := validateExecutionSealInventory(hostile, hostileManifest, hostileScope, hostileGenerated, os.Getuid()); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}

	for name, budget := range map[string]sealInventoryBudget{
		"entry count":    {maximumEntries: 2, maximumFileSize: 1 << 20, maximumTreeSize: 1 << 20},
		"per-file bytes": {maximumEntries: 1_000, maximumFileSize: 2, maximumTreeSize: 1 << 20},
		"total bytes":    {maximumEntries: 1_000, maximumFileSize: 1 << 20, maximumTreeSize: 4},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateExecutionSealInventoryWithBudget(root, manifest, scope, generated, os.Getuid(), budget); err == nil {
				t.Fatalf("%s budget was not enforced", name)
			}
		})
	}
}

func TestExecutionSealPrunesOutOfScopeAndQualificationOnlyPaths(t *testing.T) {
	root := t.TempDir()
	for _, value := range []string{
		"kept.txt",
		"legacy/codefly.txt",
		"dist-management-seed-test/test.js",
		"artifacts/bootstrap-candidate.payload",
	} {
		writeSealFixtureFile(t, root, value, value)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := signerSourceManifest{}
	for _, value := range []string{"kept.txt", "legacy/codefly.txt"} {
		digest, err := sha256File(filepath.Join(root, filepath.FromSlash(value)))
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files = append(manifest.Files, struct {
			Path       string `json:"path"`
			Executable bool   `json:"executable"`
			SHA256     string `json:"sha256"`
		}{Path: value, SHA256: digest})
	}
	if err := pruneExecutionTree(root, manifest, map[string]bool{"kept.txt": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "kept.txt")); err != nil {
		t.Fatal("retained governed source was removed")
	}
	for _, removed := range []string{"legacy", ".git", "dist-management-seed-test", "artifacts/bootstrap-candidate.payload"} {
		if _, err := os.Lstat(filepath.Join(root, removed)); !os.IsNotExist(err) {
			t.Fatalf("qualification-only path remains: %s", removed)
		}
	}
}

func validSealInventoryFixture(t *testing.T) (string, signerSourceManifest, managementSeedSealScope, bootstrapSealInventory) {
	t.Helper()
	root := t.TempDir()
	writeSealFixtureFile(t, root, "governed.txt", "reviewed")
	for _, value := range sealedGeneratedRoots {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(value)), 0o700); err != nil {
			t.Fatal(err)
		}
		writeSealFixtureFile(t, root, value+"/.inventory", value)
	}
	for _, name := range []string{"README.md", "a-b", "a_b", "pulumi-resource-aws"} {
		writeSealFixtureFile(t, root, "node_modules/"+name, name)
	}
	for _, value := range sealedGeneratedFiles {
		writeSealFixtureFile(t, root, value, value)
	}
	for _, value := range sealedEmptyDirectories {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(value)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := sha256File(filepath.Join(root, "governed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := signerSourceManifest{}
	manifest.Files = append(manifest.Files, struct {
		Path       string `json:"path"`
		Executable bool   `json:"executable"`
		SHA256     string `json:"sha256"`
	}{Path: "governed.txt", SHA256: digest})
	scope := managementSeedSealScope{
		APIVersion:  "security.deus.dev/management-seed-qualification-scope/v1",
		SourceFiles: []string{"governed.txt"},
	}
	return root, manifest, scope, fixtureGeneratedInventory(t, root)
}

func fixtureGeneratedInventory(t *testing.T, root string) bootstrapSealInventory {
	t.Helper()
	entries := make([]bootstrapSealInventoryEntry, 0)
	for _, generatedRoot := range sealedGeneratedRoots {
		entries = append(entries, bootstrapSealInventoryEntry{Path: generatedRoot, Type: "directory"})
		entries = append(entries, fixtureGeneratedFileEntry(t, root, generatedRoot+"/.inventory"))
	}
	for _, name := range []string{"README.md", "a-b", "a_b", "pulumi-resource-aws"} {
		entries = append(entries, fixtureGeneratedFileEntry(t, root, "node_modules/"+name))
	}
	for _, value := range sealedGeneratedFiles {
		if value == "artifacts/bootstrap-candidate.json" || value == "artifacts/bootstrap-seal-inventory.json" {
			continue
		}
		entries = append(entries, fixtureGeneratedFileEntry(t, root, value))
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
	var total int64
	var maximum int64
	for _, entry := range entries {
		if entry.Type == "file" {
			total += entry.Size
			if entry.Size > maximum {
				maximum = entry.Size
			}
		}
	}
	documentDigest, err := sha256File(filepath.Join(root, "artifacts", "bootstrap-seal-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidateDigest, err := sha256File(filepath.Join(root, "artifacts", "bootstrap-candidate.json"))
	if err != nil {
		t.Fatal(err)
	}
	return bootstrapSealInventory{
		APIVersion:      "security.deus.dev/bootstrap-seal-inventory/v1",
		EntryCount:      len(entries),
		TotalFileBytes:  total,
		MaximumFileSize: maximum,
		Entries:         entries,
		DocumentSHA256:  documentDigest,
		CandidateSHA256: candidateDigest,
	}
}

func fixtureGeneratedFileEntry(t *testing.T, root, relative string) bootstrapSealInventoryEntry {
	t.Helper()
	value := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Stat(value)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := sha256File(value)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrapSealInventoryEntry{
		Path:       relative,
		Type:       "file",
		Size:       info.Size(),
		Executable: info.Mode().Perm()&0o111 != 0,
		SHA256:     digest,
	}
}

func writeSealFixtureFile(t *testing.T, root, relative, contents string) {
	t.Helper()
	value := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(value), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(value, []byte(contents), 0o600); err != nil {
		t.Fatal(fmt.Errorf("write %s: %w", relative, err))
	}
}

func TestSealInventoryErrorMessagesDoNotExposeFileContents(t *testing.T) {
	root, manifest, scope, generated := validSealInventoryFixture(t)
	secret := "must-not-appear-in-errors"
	writeSealFixtureFile(t, root, "unexpected-secret", secret)
	err := validateExecutionSealInventory(root, manifest, scope, generated, os.Getuid())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe seal error: %v", err)
	}
}

func TestSealBudgetAdmitsPinnedAWSProvider(t *testing.T) {
	const observedLinuxAMD64ProviderSize = 892_236_066
	if sealMaximumFileSize <= observedLinuxAMD64ProviderSize {
		t.Fatalf("seal file budget %d rejects the pinned provider size %d", sealMaximumFileSize, observedLinuxAMD64ProviderSize)
	}
}
