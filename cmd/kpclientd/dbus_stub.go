//go:build !linux

package main

import "errors"

func ownBusName(string) (func() error, error) {
	return nil, errors.New("D-Bus name ownership is unsupported on this platform")
}
