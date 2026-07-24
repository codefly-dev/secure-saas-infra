//go:build linux || darwin

package main

import (
	"os"
	"syscall"
)

func platformFileUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
