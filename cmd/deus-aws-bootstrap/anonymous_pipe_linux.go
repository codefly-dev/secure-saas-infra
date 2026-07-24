//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func requireAnonymousPipe(file *os.File, label string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return fmt.Errorf("%s must be an anonymous pipe", label)
	}
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		return fmt.Errorf("resolve %s descriptor: %w", label, err)
	}
	if !strings.HasPrefix(target, "pipe:[") || !strings.HasSuffix(target, "]") {
		return fmt.Errorf("%s must be an anonymous pipe", label)
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "pipe:["), "]")
	if inode == "" {
		return fmt.Errorf("%s must be an anonymous pipe", label)
	}
	for _, character := range inode {
		if character < '0' || character > '9' {
			return fmt.Errorf("%s must be an anonymous pipe", label)
		}
	}
	return nil
}
