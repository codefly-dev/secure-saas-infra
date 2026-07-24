//go:build !linux

package main

import "errors"

func installRuntimeSudoers(_ []string) error {
	return errors.New("install-sudoers requires Linux")
}
