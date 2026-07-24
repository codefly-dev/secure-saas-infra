//go:build !linux

package main

import (
	"fmt"
	"os"
)

func requireAnonymousPipe(file *os.File, label string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return fmt.Errorf("%s must be an anonymous pipe", label)
	}
	return nil
}
