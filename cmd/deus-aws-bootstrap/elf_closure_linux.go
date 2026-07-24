//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const systemRuntimeClosureAPIVersion = "security.deus.dev/system-runtime-closure/v1"

type systemFileBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type systemRuntimeClosure struct {
	APIVersion   string              `json:"apiVersion"`
	Architecture string              `json:"architecture"`
	Loaders      []systemFileBinding `json:"loaders"`
	Libraries    []systemFileBinding `json:"libraries"`
}

type runtimeArtifactProvenance struct {
	File         string `json:"file"`
	SHA256       string `json:"sha256"`
	Verification string `json:"verification"`
}

type awsRuntimeArtifactProvenance struct {
	runtimeArtifactProvenance
	SigningKeyFingerprint string `json:"signingKeyFingerprint"`
}

type bootstrapRuntimeProvenance struct {
	APIVersion   string `json:"apiVersion"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Artifacts    struct {
		Go     runtimeArtifactProvenance    `json:"go"`
		Node   runtimeArtifactProvenance    `json:"node"`
		Pulumi runtimeArtifactProvenance    `json:"pulumi"`
		AWSCLI awsRuntimeArtifactProvenance `json:"awsCli"`
	} `json:"artifacts"`
	Installed struct {
		GoSHA256         string `json:"goSha256"`
		NodeSHA256       string `json:"nodeSha256"`
		PulumiTreeDigest string `json:"pulumiTreeDigest"`
		AWSCLITreeDigest string `json:"awsCliTreeDigest"`
	} `json:"installed"`
	SystemRuntime systemRuntimeClosure `json:"systemRuntime"`
}

type elfAnalysis struct {
	closure            systemRuntimeClosure
	dynamicExecutables []string
}

func writeRuntimeELFClosure(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("runtime-elf-closure requires OS root")
	}
	if len(args) != 4 || args[0] != "--root" || args[2] != "--output" {
		return errors.New("runtime-elf-closure requires --root <runtime> --output <file>")
	}
	root, err := filepath.EvalSymlinks(args[1])
	if err != nil || !filepath.IsAbs(root) {
		return errors.New("runtime-elf-closure root is unavailable")
	}
	if err := requireRootOwnedDirectory(root); err != nil {
		return err
	}
	output := filepath.Clean(args[3])
	if !withinPath(root, output) || filepath.Dir(output) != root {
		return errors.New("runtime-elf-closure output must be a direct runtime child")
	}
	analysis, err := analyzeELFClosure([]string{
		filepath.Join(root, "bin", "node"),
		filepath.Join(root, "toolchains", "pulumi"),
		filepath.Join(root, "toolchains", "aws-cli"),
	}, root)
	if err != nil {
		return err
	}
	if len(analysis.closure.Loaders) == 0 {
		return errors.New("runtime ELF closure contains no authenticated dynamic loader")
	}
	contents, err := json.MarshalIndent(analysis.closure, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runtime ELF closure: %w", err)
	}
	contents = append(contents, '\n')
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("create runtime ELF closure: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write runtime ELF closure: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close runtime ELF closure: %w", err)
	}
	return nil
}

func analyzeELFClosure(inputs []string, ownedRoot string) (elfAnalysis, error) {
	queue := make([]string, 0)
	queued := make(map[string]bool)
	for _, input := range inputs {
		if err := addELFInputs(input, &queue, queued); err != nil {
			return elfAnalysis{}, err
		}
	}
	loaders := make(map[string]bool)
	external := make(map[string]bool)
	dynamicExecutables := make(map[string]bool)
	for _, optional := range []string{
		"libgcc_s.so.1",
		"libnss_dns.so.2",
		"libnss_files.so.2",
		"libnss_systemd.so.2",
		"libresolv.so.2",
	} {
		resolved, resolveErr := resolveRuntimeFile(optional, "/", defaultELFLibraryPaths())
		if resolveErr != nil {
			continue
		}
		external[resolved] = true
		if err := enqueueELF(resolved, &queue, queued); err != nil {
			return elfAnalysis{}, err
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		binary, err := elf.Open(current)
		if err != nil {
			return elfAnalysis{}, fmt.Errorf("parse ELF runtime file %s: %w", current, err)
		}
		interpreter := ""
		if section := binary.Section(".interp"); section != nil {
			contents, readErr := section.Data()
			if readErr != nil {
				_ = binary.Close()
				return elfAnalysis{}, fmt.Errorf("read ELF interpreter for %s: %w", current, readErr)
			}
			interpreter = strings.TrimRight(string(contents), "\x00")
		}
		runpaths, err := elfSearchPaths(binary, filepath.Dir(current))
		if err != nil {
			_ = binary.Close()
			return elfAnalysis{}, fmt.Errorf("read ELF search path for %s: %w", current, err)
		}
		libraries, err := binary.ImportedLibraries()
		_ = binary.Close()
		if err != nil {
			return elfAnalysis{}, fmt.Errorf("read ELF dependencies for %s: %w", current, err)
		}
		if interpreter != "" {
			resolved, err := resolveRuntimeFile(interpreter, filepath.Dir(current), runpaths)
			if err != nil {
				return elfAnalysis{}, fmt.Errorf("resolve ELF interpreter for %s: %w", current, err)
			}
			loaders[resolved] = true
			dynamicExecutables[current] = true
			if err := enqueueELF(resolved, &queue, queued); err != nil {
				return elfAnalysis{}, err
			}
		}
		for _, library := range libraries {
			resolved, err := resolveRuntimeFile(library, filepath.Dir(current), runpaths)
			if err != nil {
				return elfAnalysis{}, fmt.Errorf("resolve %s required by %s: %w", library, current, err)
			}
			if !withinPath(ownedRoot, resolved) {
				external[resolved] = true
			}
			if err := enqueueELF(resolved, &queue, queued); err != nil {
				return elfAnalysis{}, err
			}
		}
		if len(queued) > 10_000 || len(external) > 512 {
			return elfAnalysis{}, errors.New("runtime ELF closure is excessive")
		}
	}
	for loader := range loaders {
		if !withinPath(ownedRoot, loader) {
			external[loader] = true
		}
	}
	for value := range external {
		for _, optimized := range glibcHWCapsVariants(value) {
			external[optimized] = true
		}
	}
	closure := systemRuntimeClosure{
		APIVersion:   systemRuntimeClosureAPIVersion,
		Architecture: runtime.GOARCH,
	}
	for value := range loaders {
		if withinPath(ownedRoot, value) {
			continue
		}
		binding, err := bindSystemFile(value, true)
		if err != nil {
			return elfAnalysis{}, err
		}
		closure.Loaders = append(closure.Loaders, binding)
		delete(external, value)
	}
	for value := range external {
		binding, err := bindSystemFile(value, false)
		if err != nil {
			return elfAnalysis{}, err
		}
		closure.Libraries = append(closure.Libraries, binding)
	}
	sort.Slice(closure.Loaders, func(i, j int) bool { return closure.Loaders[i].Path < closure.Loaders[j].Path })
	sort.Slice(closure.Libraries, func(i, j int) bool { return closure.Libraries[i].Path < closure.Libraries[j].Path })
	executables := make([]string, 0, len(dynamicExecutables))
	for value := range dynamicExecutables {
		executables = append(executables, value)
	}
	sort.Strings(executables)
	return elfAnalysis{closure: closure, dynamicExecutables: executables}, nil
}

func glibcHWCapsVariants(value string) []string {
	root := filepath.Join(filepath.Dir(value), "glibc-hwcaps")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	result := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		candidate := filepath.Join(root, entry.Name(), filepath.Base(value))
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			result = append(result, resolved)
		}
	}
	return result
}

func loadBoundSystemRuntimeClosure() (systemRuntimeClosure, error) {
	contents, err := os.ReadFile(runtimeProvenancePath)
	if err != nil {
		return systemRuntimeClosure{}, fmt.Errorf("read runtime provenance for confinement: %w", err)
	}
	envelope, err := parseBootstrapRuntimeProvenance(contents)
	if err != nil {
		return systemRuntimeClosure{}, fmt.Errorf("parse runtime provenance for confinement: %w", err)
	}
	closure := envelope.SystemRuntime
	if closure.APIVersion != systemRuntimeClosureAPIVersion ||
		closure.Architecture != runtime.GOARCH ||
		len(closure.Loaders) == 0 || len(closure.Loaders) > 8 ||
		len(closure.Libraries) > 512 {
		return systemRuntimeClosure{}, errors.New("runtime provenance system closure is malformed")
	}
	seen := make(map[string]bool)
	last := ""
	for index, collection := range [][]systemFileBinding{closure.Loaders, closure.Libraries} {
		for _, expected := range collection {
			if expected.Path <= last || seen[expected.Path] || !isSHA256(expected.SHA256) {
				return systemRuntimeClosure{}, errors.New("runtime provenance system closure is not exact and sorted")
			}
			observed, err := bindSystemFile(expected.Path, index == 0)
			if err != nil || observed != expected {
				return systemRuntimeClosure{}, fmt.Errorf("system runtime binding changed at %s", expected.Path)
			}
			seen[expected.Path] = true
			last = expected.Path
		}
		last = ""
	}
	return closure, nil
}

func parseBootstrapRuntimeProvenance(contents []byte) (bootstrapRuntimeProvenance, error) {
	var provenance bootstrapRuntimeProvenance
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&provenance); err != nil {
		return bootstrapRuntimeProvenance{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return bootstrapRuntimeProvenance{}, errors.New("runtime provenance has trailing content")
	}
	if provenance.APIVersion != "security.deus.dev/bootstrap-runtime-provenance/v1" ||
		provenance.Platform != "linux" || provenance.Architecture != runtime.GOARCH ||
		provenance.SystemRuntime.Architecture != provenance.Architecture {
		return bootstrapRuntimeProvenance{}, errors.New("runtime provenance envelope is malformed")
	}
	for _, artifact := range []runtimeArtifactProvenance{
		provenance.Artifacts.Go,
		provenance.Artifacts.Node,
		provenance.Artifacts.Pulumi,
	} {
		if artifact.File == "" || len(artifact.File) > 256 || !isSHA256(artifact.SHA256) ||
			artifact.Verification != "authenticated-host-kit-pinned-sha256" {
			return bootstrapRuntimeProvenance{}, errors.New("runtime provenance artifact is malformed")
		}
	}
	aws := provenance.Artifacts.AWSCLI
	if aws.File == "" || len(aws.File) > 256 || !isSHA256(aws.SHA256) ||
		aws.Verification != "aws-cli-team-pgp" ||
		aws.SigningKeyFingerprint != "FB5DB77FD5C118B80511ADA8A6310ACC4672475C" {
		return bootstrapRuntimeProvenance{}, errors.New("AWS CLI runtime provenance is malformed")
	}
	for _, digest := range []string{
		provenance.Installed.GoSHA256,
		provenance.Installed.NodeSHA256,
		provenance.Installed.PulumiTreeDigest,
		provenance.Installed.AWSCLITreeDigest,
	} {
		if !isSHA256(digest) {
			return bootstrapRuntimeProvenance{}, errors.New("installed runtime provenance digest is malformed")
		}
	}
	return provenance, nil
}

func validateExecutionELFClosure(bound systemRuntimeClosure) error {
	analysis, err := analyzeELFClosure([]string{executionRoot}, executionRoot)
	if err != nil {
		return fmt.Errorf("analyze sealed execution ELF closure: %w", err)
	}
	provider, err := filepath.EvalSymlinks(
		filepath.Join(pulumiHome, "plugins", "resource-aws-v7.27.0", "pulumi-resource-aws"),
	)
	if err != nil {
		return fmt.Errorf("resolve sealed AWS provider: %w", err)
	}
	for _, executable := range analysis.dynamicExecutables {
		if executable != provider {
			return fmt.Errorf("sealed execution root contains unapproved dynamic executable %s", executable)
		}
	}
	boundFiles := make(map[string]string)
	for _, entry := range append(append([]systemFileBinding{}, bound.Loaders...), bound.Libraries...) {
		boundFiles[entry.Path] = entry.SHA256
	}
	for _, entry := range append(append([]systemFileBinding{}, analysis.closure.Loaders...), analysis.closure.Libraries...) {
		if boundFiles[entry.Path] != entry.SHA256 {
			return fmt.Errorf("sealed execution requires unbound system runtime file %s", entry.Path)
		}
	}
	return nil
}

func credentialExecutableMappings() ([]string, error) {
	bound, err := loadBoundSystemRuntimeClosure()
	if err != nil {
		return nil, err
	}
	if err := validateExecutionELFClosure(bound); err != nil {
		return nil, err
	}
	allowed := make(map[string]bool)
	for _, value := range credentialExecutablePaths() {
		resolved, err := filepath.EvalSymlinks(value)
		if err != nil {
			return nil, fmt.Errorf("resolve credential executable mapping %s: %w", value, err)
		}
		allowed[resolved] = true
	}
	for _, entry := range append(append([]systemFileBinding{}, bound.Loaders...), bound.Libraries...) {
		allowed[entry.Path] = true
	}
	for _, root := range []string{installRoot, executionRoot} {
		err := filepath.WalkDir(root, func(value string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return nil
			}
			binary, err := elf.Open(value)
			if err != nil {
				return nil
			}
			interpreter := binary.Section(".interp")
			typeValue := binary.Type
			_ = binary.Close()
			resolved, err := filepath.EvalSymlinks(value)
			if err != nil {
				return err
			}
			if allowed[resolved] || (typeValue == elf.ET_DYN && interpreter == nil) {
				allowed[resolved] = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("inventory credential executable mappings: %w", err)
		}
	}
	result := make([]string, 0, len(allowed))
	for value := range allowed {
		if err := requireRootOwnedRegularFile(value, false); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func addELFInputs(value string, queue *[]string, queued map[string]bool) error {
	info, err := os.Lstat(value)
	if err != nil {
		return fmt.Errorf("inspect ELF input %s: %w", value, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(value)
		if err != nil {
			return fmt.Errorf("resolve ELF input %s: %w", value, err)
		}
		return addELFInputs(resolved, queue, queued)
	}
	if info.Mode().IsRegular() {
		return enqueueELF(value, queue, queued)
	}
	if !info.IsDir() {
		return fmt.Errorf("ELF input %s is not a file or directory", value)
	}
	return filepath.WalkDir(value, func(candidate string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("runtime closure contains unsupported file %s", candidate)
		}
		return enqueueELF(candidate, queue, queued)
	})
}

func enqueueELF(value string, queue *[]string, queued map[string]bool) error {
	real, err := filepath.EvalSymlinks(value)
	if err != nil {
		return fmt.Errorf("resolve runtime file %s: %w", value, err)
	}
	if queued[real] {
		return nil
	}
	file, err := os.Open(real)
	if err != nil {
		return fmt.Errorf("open runtime file %s: %w", real, err)
	}
	header := make([]byte, 4)
	count, readErr := file.Read(header)
	_ = file.Close()
	if readErr != nil || count != len(header) || string(header) != "\x7fELF" {
		return nil
	}
	queued[real] = true
	*queue = append(*queue, real)
	return nil
}

func elfSearchPaths(binary *elf.File, origin string) ([]string, error) {
	result := []string{origin, filepath.Join(origin, "lib")}
	for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		values, err := binary.DynString(tag)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			for _, entry := range strings.Split(value, ":") {
				if entry == "" {
					return nil, errors.New("empty ELF runtime search path is forbidden")
				}
				entry = strings.ReplaceAll(entry, "${ORIGIN}", origin)
				entry = strings.ReplaceAll(entry, "$ORIGIN", origin)
				if !filepath.IsAbs(entry) {
					return nil, fmt.Errorf("relative ELF runtime search path %s is forbidden", entry)
				}
				result = append(result, filepath.Clean(entry))
			}
		}
	}
	result = append(result, defaultELFLibraryPaths()...)
	return uniqueStrings(result), nil
}

func defaultELFLibraryPaths() []string {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64", "/lib", "/usr/lib"}
	case "arm64":
		return []string{"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/lib64", "/usr/lib64", "/lib", "/usr/lib"}
	default:
		return nil
	}
}

func resolveRuntimeFile(name, origin string, search []string) (string, error) {
	candidates := make([]string, 0)
	if filepath.IsAbs(name) {
		candidates = append(candidates, name)
	} else if strings.ContainsRune(name, filepath.Separator) {
		candidates = append(candidates, filepath.Join(origin, name))
	} else {
		for _, directory := range search {
			candidates = append(candidates, filepath.Join(directory, name))
		}
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		return filepath.Clean(resolved), nil
	}
	return "", fmt.Errorf("no exact runtime file resolves %s", name)
}

func bindSystemFile(value string, executable bool) (systemFileBinding, error) {
	clean := filepath.Clean(value)
	if !filepath.IsAbs(clean) || (!strings.HasPrefix(clean, "/lib/") && !strings.HasPrefix(clean, "/usr/lib/")) {
		return systemFileBinding{}, fmt.Errorf("external runtime file is outside system libraries: %s", value)
	}
	if err := requireRootOwnedRegularFile(clean, executable); err != nil {
		return systemFileBinding{}, err
	}
	digest, err := digestFile(clean)
	if err != nil {
		return systemFileBinding{}, err
	}
	return systemFileBinding{Path: clean, SHA256: digest}, nil
}

func digestFile(value string) (string, error) {
	contents, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("read trusted runtime file %s: %w", value, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(contents)), nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func withinPath(root, value string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(value))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
