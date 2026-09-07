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
			cmd.SetArgs(normalizeLegacyArgs(cmd, []string{"-log_dir", "/missing", arg}))

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
		logDir, err := cmd.Flags().GetString("log_dir")
		if err != nil {
			t.Fatalf("get log_dir: %v", err)
		}
		if logDir != "/missing" {
			t.Fatalf("log_dir = %q, want %q", logDir, "/missing")
		}
	}
	cmd.SetArgs(normalizeLegacyArgs(cmd, []string{"-log_dir", "/missing"}))

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute legacy flag: %v", err)
	}
	if !ran {
		t.Fatal("command did not run")
	}
}
