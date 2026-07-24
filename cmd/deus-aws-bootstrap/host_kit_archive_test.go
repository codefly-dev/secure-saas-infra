package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	hostKitTestTag          = "v1.2.3"
	hostKitTestRevision     = "0123456789abcdef0123456789abcdef01234567"
	hostKitTestArchitecture = "amd64"
)

func TestHostKitArchivePreflightAcceptsOnlyExactSafeMembers(t *testing.T) {
	archive := writeHostKitTestArchive(t, nil)
	if err := validateHostKitArchive(archive, hostKitTestTag, hostKitTestRevision, hostKitTestArchitecture); err != nil {
		t.Fatalf("exact host-kit archive was rejected: %v", err)
	}
	padded := writeHostKitTestArchive(t, func(value *hostKitTestArchive) {
		value.plaintextTail = make([]byte, hostKitTarPaddingMaximum)
	})
	if err := validateHostKitArchive(padded, hostKitTestTag, hostKitTestRevision, hostKitTestArchitecture); err != nil {
		t.Fatalf("one GNU tar record of zero padding was rejected: %v", err)
	}

	for name, mutate := range map[string]func(*hostKitTestArchive){
		"extra member": func(value *hostKitTestArchive) {
			value.extra = &tar.Header{Name: "./attacker", Typeflag: tar.TypeReg, Mode: 0o444, Size: 1, ModTime: time.Unix(0, 0)}
			value.extraContents = []byte("x")
		},
		"duplicate member": func(value *hostKitTestArchive) {
			value.extra = &tar.Header{Name: "./RELEASE", Typeflag: tar.TypeReg, Mode: 0o444, Size: int64(len(value.files["RELEASE"])), ModTime: time.Unix(0, 0)}
			value.extraContents = value.files["RELEASE"]
		},
		"path traversal": func(value *hostKitTestArchive) {
			value.extra = &tar.Header{Name: "./../escape", Typeflag: tar.TypeReg, Mode: 0o444, Size: 1, ModTime: time.Unix(0, 0)}
			value.extraContents = []byte("x")
		},
		"symbolic link": func(value *hostKitTestArchive) {
			value.types["RELEASE"] = tar.TypeSymlink
			value.links["RELEASE"] = "/etc/passwd"
		},
		"checksum substitution": func(value *hostKitTestArchive) {
			value.files["deus-aws-bootstrap"] = []byte("substituted")
		},
		"non-zero tar tail": func(value *hostKitTestArchive) {
			value.plaintextTail = []byte("not padding")
		},
	} {
		t.Run(name, func(t *testing.T) {
			hostile := writeHostKitTestArchive(t, mutate)
			if err := validateHostKitArchive(hostile, hostKitTestTag, hostKitTestRevision, hostKitTestArchitecture); err == nil {
				t.Fatalf("%s host-kit archive was accepted", name)
			}
		})
	}
}

func TestHostKitArchivePreflightRejectsTrailingCompressedContent(t *testing.T) {
	archive := writeHostKitTestArchive(t, nil)
	file, err := os.OpenFile(archive, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("trailing")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateHostKitArchive(archive, hostKitTestTag, hostKitTestRevision, hostKitTestArchitecture); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing archive content was accepted: %v", err)
	}
}

func TestHostKitArchiveReleaseTagParserFailsClosed(t *testing.T) {
	for _, valid := range []string{"v1.2.3", "v1.2.3-rc.1", "v1.2.3+build.7"} {
		if !validReleaseTag(valid) {
			t.Fatalf("valid release tag was rejected: %s", valid)
		}
	}
	for _, hostile := range []string{"v+++++", "v1.2", "v01.2.3", "v1.2.3+", "v1.2.3+bad+more", "v1.2.3 shell"} {
		if validReleaseTag(hostile) {
			t.Fatalf("hostile release tag was accepted: %s", hostile)
		}
	}
}

type hostKitTestArchive struct {
	files         map[string][]byte
	types         map[string]byte
	links         map[string]string
	extra         *tar.Header
	extraContents []byte
	plaintextTail []byte
}

func writeHostKitTestArchive(t *testing.T, mutate func(*hostKitTestArchive)) string {
	t.Helper()
	files := make(map[string][]byte, len(hostKitFileModes))
	for name := range hostKitFileModes {
		if name != "SHA256SUMS" {
			files[name] = []byte("contents:" + name + "\n")
		}
	}
	files["RELEASE"] = []byte(fmt.Sprintf("releaseTag=%s\nsourceRevision=%s\narchitecture=%s\n", hostKitTestTag, hostKitTestRevision, hostKitTestArchitecture))
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var checksums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&checksums, "%x  %s\n", sha256.Sum256(files[name]), name)
	}
	files["SHA256SUMS"] = []byte(checksums.String())
	value := &hostKitTestArchive{files: files, types: map[string]byte{}, links: map[string]string{}}
	if mutate != nil {
		mutate(value)
	}
	archive := filepath.Join(t.TempDir(), "host-kit.tar.gz")
	output, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(output)
	writer := tar.NewWriter(compressed)
	directories := make([]string, 0, len(hostKitDirectoryModes))
	for name := range hostKitDirectoryModes {
		directories = append(directories, name)
	}
	sort.Strings(directories)
	for _, name := range directories {
		headerName := "./" + name + "/"
		if name == "." {
			headerName = "./"
		}
		if err := writer.WriteHeader(&tar.Header{Name: headerName, Typeflag: tar.TypeDir, Mode: hostKitDirectoryModes[name], ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
	}
	fileNames := make([]string, 0, len(value.files))
	for name := range value.files {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		contents := value.files[name]
		typeFlag := value.types[name]
		if typeFlag == 0 {
			typeFlag = tar.TypeReg
		}
		size := int64(len(contents))
		if typeFlag != tar.TypeReg && typeFlag != tar.TypeRegA {
			size = 0
		}
		header := &tar.Header{Name: "./" + name, Typeflag: typeFlag, Mode: hostKitFileModes[name], Size: size, Linkname: value.links[name], ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := writer.Write(contents); err != nil {
				t.Fatal(err)
			}
		}
	}
	if value.extra != nil {
		value.extra.Format = tar.FormatUSTAR
		if err := writer.WriteHeader(value.extra); err != nil {
			t.Fatal(err)
		}
		if len(value.extraContents) > 0 {
			if _, err := writer.Write(value.extraContents); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if len(value.plaintextTail) > 0 {
		if _, err := compressed.Write(value.plaintextTail); err != nil {
			t.Fatal(err)
		}
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return archive
}
