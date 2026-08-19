//go:build windows

package parse

import "errors"

func makeFIFO(path string) error { return errors.New("not supported") }
