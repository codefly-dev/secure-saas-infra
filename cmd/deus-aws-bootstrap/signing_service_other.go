//go:build !linux

package main

import (
	"errors"
	"io"
)

const (
	signingPrepareCgroup = ""
	signingReviewCgroup  = ""
)

func runSigningReviewService(_ []string, _ []string, _, _ io.Writer) error {
	return errors.New("signing-review-service requires Linux")
}

func requireSignerServicePhase(_ string) error {
	return errors.New("signing requires Linux systemd isolation")
}
