//go:build !linux

package main

import "errors"

func prepareExecutionTreeForSeal(_ string, _ string, _ string, _ int) (func(string, int) error, error) {
	return nil, errors.New("execution seal inventory requires Linux")
}
