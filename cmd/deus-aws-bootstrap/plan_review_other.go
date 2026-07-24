//go:build !linux

package main

import "errors"

func exportPlanReview(_ []string) error {
	return errors.New("export-plan-review requires Linux")
}
