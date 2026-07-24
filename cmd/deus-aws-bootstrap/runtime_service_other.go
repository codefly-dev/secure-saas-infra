//go:build !linux

package main

import (
	"errors"
	"io"
)

func runRuntimeService(_ []string, _ []string, _ io.Reader, _, _ io.Writer) error {
	return errors.New("runtime-service requires Linux")
}

func requireExclusiveRuntimeService() error {
	return errors.New("credential execution requires Linux systemd isolation")
}
