package utils

import (
	"errors"
	"os"
)

func BothExists(a, b string) bool {
	if Exists(a) && Exists(b) {
		return true
	}
	return false
}

func BothNotExists(a, b string) bool {
	if !Exists(a) && !Exists(b) {
		return true
	}
	return false
}

func Exists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		panic(err)
	}
}
