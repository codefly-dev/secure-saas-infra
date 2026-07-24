package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	hostKitArchiveMaximumSize = 100 * 1024 * 1024
	hostKitTarPaddingMaximum  = 20 * 512
)

var hostKitFileModes = map[string]int64{
	"RELEASE":                                        0o444,
	"SHA256SUMS":                                     0o444,
	"deus-aws-bootstrap":                             0o555,
	"management-seed-source-manifest.json":           0o444,
	"scripts/bootstrap-signing-stage0.mjs":           0o444,
	"scripts/credentialed-bootstrap-stage1.mjs":      0o444,
	"scripts/install-bootstrap-runtime":              0o555,
	"scripts/write-bootstrap-runtime-provenance.mjs": 0o444,
	"security/bootstrap-host-toolchain.json":         0o444,
	"security/bootstrap-qualification-trust.json":    0o444,
}

var hostKitDirectoryModes = map[string]int64{
	".":        0o755,
	"scripts":  0o755,
	"security": 0o755,
}

func verifyHostKitArchive(args []string) error {
	values, err := exactFlagValues(args, []string{"--archive", "--tag", "--revision", "--architecture"})
	if err != nil {
		return err
	}
	if !validReleaseTag(values["--tag"]) || len(values["--revision"]) != 40 || !lowerHex(values["--revision"]) || (values["--architecture"] != "amd64" && values["--architecture"] != "arm64") {
		return errors.New("host-kit archive identity arguments are invalid")
	}
	return validateHostKitArchive(values["--archive"], values["--tag"], values["--revision"], values["--architecture"])
}

func validateHostKitArchive(archivePath, tag, revision, architecture string) error {
	archive, err := os.OpenFile(filepath.Clean(archivePath), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open host-kit archive: %w", err)
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > hostKitArchiveMaximumSize {
		return errors.New("host-kit archive must be a bounded direct regular file")
	}
	buffered := bufio.NewReader(archive)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return fmt.Errorf("open host-kit gzip stream: %w", err)
	}
	compressed.Multistream(false)
	reader := tar.NewReader(compressed)
	seen := make(map[string]bool, len(hostKitFileModes)+len(hostKitDirectoryModes))
	contents := make(map[string][]byte, len(hostKitFileModes))
	var total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read host-kit archive: %w", err)
		}
		name, err := normalizeHostKitMember(header.Name)
		if err != nil || seen[name] {
			return fmt.Errorf("host-kit archive contains an unsafe or duplicate member %q", header.Name)
		}
		seen[name] = true
		if header.Uid != 0 || header.Gid != 0 || header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || !header.ModTime.Equal(time.Unix(0, 0)) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() {
			return fmt.Errorf("host-kit member metadata is unsafe at %s", name)
		}
		if mode, ok := hostKitDirectoryModes[name]; ok {
			if header.Typeflag != tar.TypeDir || header.Size != 0 || header.Mode != mode {
				return fmt.Errorf("host-kit directory metadata differs at %s", name)
			}
			continue
		}
		mode, ok := hostKitFileModes[name]
		if !ok || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Mode != mode || header.Size <= 0 || header.Size > hostKitArchiveMaximumSize {
			return fmt.Errorf("host-kit archive contains an unexpected or unsafe file at %s", name)
		}
		total += header.Size
		if total > hostKitArchiveMaximumSize {
			return errors.New("host-kit expanded contents exceed the byte budget")
		}
		value, err := io.ReadAll(io.LimitReader(reader, hostKitArchiveMaximumSize+1))
		if err != nil || int64(len(value)) != header.Size {
			return fmt.Errorf("host-kit member changed or truncated at %s", name)
		}
		contents[name] = value
	}
	padding, err := io.ReadAll(io.LimitReader(compressed, hostKitTarPaddingMaximum+1))
	if err != nil {
		return fmt.Errorf("read host-kit tar padding: %w", err)
	}
	if len(padding) > hostKitTarPaddingMaximum {
		return errors.New("host-kit tar padding exceeds one record")
	}
	for _, value := range padding {
		if value != 0 {
			return errors.New("host-kit tar has non-zero content after its end marker")
		}
	}
	if err := compressed.Close(); err != nil {
		return fmt.Errorf("close host-kit gzip stream: %w", err)
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		return errors.New("host-kit archive has trailing compressed content")
	}
	if len(seen) != len(hostKitFileModes)+len(hostKitDirectoryModes) {
		return errors.New("host-kit archive member inventory is incomplete")
	}
	for value := range hostKitFileModes {
		if !seen[value] {
			return fmt.Errorf("host-kit archive lacks %s", value)
		}
	}
	for value := range hostKitDirectoryModes {
		if !seen[value] {
			return fmt.Errorf("host-kit archive lacks directory %s", value)
		}
	}
	if string(contents["RELEASE"]) != fmt.Sprintf("releaseTag=%s\nsourceRevision=%s\narchitecture=%s\n", tag, revision, architecture) {
		return errors.New("host-kit RELEASE identity differs from the approved release")
	}
	if err := validateHostKitChecksums(contents); err != nil {
		return err
	}
	return nil
}

func validateHostKitChecksums(contents map[string][]byte) error {
	names := make([]string, 0, len(hostKitFileModes)-1)
	for name := range hostKitFileModes {
		if name != "SHA256SUMS" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	lines := strings.Split(strings.TrimSuffix(string(contents["SHA256SUMS"]), "\n"), "\n")
	if len(lines) != len(names) {
		return errors.New("host-kit checksum inventory is not exact")
	}
	seen := make(map[string]bool, len(names))
	for _, line := range lines {
		if len(line) < 67 || line[64:66] != "  " || !lowerHex(line[:64]) {
			return errors.New("host-kit checksum line is malformed")
		}
		name := line[66:]
		value, ok := contents[name]
		if !ok || name == "SHA256SUMS" || seen[name] {
			return errors.New("host-kit checksum inventory contains an unexpected path")
		}
		seen[name] = true
		if fmt.Sprintf("%x", sha256.Sum256(value)) != line[:64] {
			return fmt.Errorf("host-kit checksum differs at %s", name)
		}
	}
	if len(seen) != len(names) {
		return errors.New("host-kit checksum inventory is incomplete")
	}
	return nil
}

func normalizeHostKitMember(value string) (string, error) {
	if !strings.HasPrefix(value, "./") || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return "", errors.New("unsafe archive member")
	}
	cleaned := strings.TrimSuffix(strings.TrimPrefix(value, "./"), "/")
	if cleaned == "" {
		cleaned = "."
	}
	if cleaned != "." && (!filepath.IsLocal(cleaned) || filepath.ToSlash(filepath.Clean(cleaned)) != cleaned) {
		return "", errors.New("unsafe archive member")
	}
	return cleaned, nil
}

func exactFlagValues(args, names []string) (map[string]string, error) {
	if len(args) != len(names)*2 {
		return nil, errors.New("host-kit archive verification requires exact archive and release identity flags")
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	values := make(map[string]string, len(names))
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if !wanted[name] || values[name] != "" || value == "" {
			return nil, errors.New("host-kit archive verification received an unknown, duplicate, or empty flag")
		}
		values[name] = value
	}
	return values, nil
}

func validReleaseTag(value string) bool {
	if len(value) < 6 || value[0] != 'v' || strings.ContainsAny(value, "/\\\x00") {
		return false
	}
	body := value[1:]
	core := body
	if separator := strings.IndexAny(body, "+-"); separator >= 0 {
		core = body[:separator]
		suffix := body[separator+1:]
		if suffix == "" {
			return false
		}
		for _, character := range suffix {
			if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '-' {
				return false
			}
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
