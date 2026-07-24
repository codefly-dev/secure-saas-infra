//go:build !linux

package main

import "errors"

func installSignerSudoers(_ []string) error {
	return errors.New("install-signer-sudoers requires Linux")
}
