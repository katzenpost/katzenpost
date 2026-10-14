// SPDX-License-Identifier: AGPL-3.0-only

package utils

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var envReference = regexp.MustCompile(`\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)?`)

func ExpandUnixSocketPath(path string) (string, error) {
	var err error
	expanded := path
	if !strings.HasPrefix(path, "@") {
		expanded = envReference.ReplaceAllStringFunc(path, func(ref string) string {
			name := strings.Trim(ref[1:], "{}")
			value := os.Getenv(name)
			switch {
			case err != nil:
			case name == "":
				err = fmt.Errorf("unix socket path %q: invalid environment variable reference", path)
			case value == "":
				err = fmt.Errorf("unix socket path %q: environment variable %s is unset or empty", path, name)
			}
			return value
		})
	}
	if err != nil {
		return "", err
	}
	if expanded == "" || expanded == "@" {
		return "", fmt.Errorf("unix socket path %q: empty unix socket address", path)
	}
	return expanded, nil
}
