//go:build !linux

package main

import (
	"errors"
	"io"
	"os"
)

func disableProcessDumpability() error {
	return nil
}

func requirePtraceIsolation() error {
	return errors.New("ptrace isolation requires Linux")
}

func confineCredentialExecution(string) error {
	return nil
}

func writeRuntimeELFClosure([]string) error {
	return errors.New("runtime ELF closure requires Linux")
}

func createSealedBundle(_ []byte) (*os.File, error) {
	return nil, errors.New("sealed signing bundles require Linux")
}

func readSealedSigningBundle(_ io.Reader) ([]byte, error) {
	return nil, errors.New("sealed signing bundles require Linux")
}
