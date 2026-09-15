package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

func TestVersionFlags(t *testing.T) {
	for _, arg := range []string{"-v", "--version"} {
		t.Run(arg, func(t *testing.T) {
			cmd := newRootCommand()
			ran := false
			cmd.Run = func(cmd *cobra.Command, args []string) { ran = true }
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(normalizeLegacyArgs(cmd, []string{"-validate-only", arg}))

			if err := fang.Execute(context.Background(), cmd, fang.WithVersion("test-version")); err != nil {
				t.Fatalf("execute %s: %v: %s", arg, err, stderr.String())
			}
			if ran {
				t.Fatalf("command ran for %s", arg)
			}
			if !strings.Contains(stdout.String(), "test-version") {
				t.Fatalf("version output for %s did not contain version: %q", arg, stdout.String())
			}
		})
	}
}

func TestLegacyFlagReachesRun(t *testing.T) {
	cmd := newRootCommand()
	ran := false
	cmd.Run = func(cmd *cobra.Command, args []string) {
		ran = true
		validateOnly, err := cmd.Flags().GetBool("validate-only")
		if err != nil {
			t.Fatalf("get validate-only: %v", err)
		}
		if !validateOnly {
			t.Fatal("legacy -validate-only flag was not parsed")
		}
	}
	cmd.SetArgs(normalizeLegacyArgs(cmd, []string{"-validate-only"}))

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute legacy flag: %v", err)
	}
	if !ran {
		t.Fatal("command did not run")
	}
}
