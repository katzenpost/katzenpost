package main

import (
	"regexp"
	"testing"
)

func TestDefaultDBusNameIsValidWellKnownName(t *testing.T) {
	// A dbus well-known name is two or more '.'-separated elements, each
	// [A-Za-z_-][A-Za-z0-9_-]*.
	re := regexp.MustCompile(`^[A-Za-z_-][A-Za-z0-9_-]*(\.[A-Za-z_-][A-Za-z0-9_-]*)+$`)
	if !re.MatchString(defaultDBusName) {
		t.Fatalf("defaultDBusName %q is not a valid dbus well-known name", defaultDBusName)
	}
}
