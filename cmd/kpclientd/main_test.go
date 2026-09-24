package main

import (
	"testing"

	"github.com/katzenpost/katzenpost/client/config"
)

func TestDefaultDBusNameIsValidWellKnownName(t *testing.T) {
	if err := config.ValidateDBusName(defaultDBusName); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "kpclientd", ".a.b", "a..b", "a.1b", ":1.5", "a b.c"} {
		if err := config.ValidateDBusName(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
