// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Command kpconfig validates Katzenpost component configuration files
// against the very same loaders the daemons use at startup. It is the
// umbrella counterpart to each daemon's --validate-only flag: the flag
// guards a single node, this guards a whole directory of generated
// configuration before it ever leaves the source of truth.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	authcfg "github.com/katzenpost/katzenpost/authority/voting/server/config"
	clientcfg "github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/common/tomlstrict"
	couriercfg "github.com/katzenpost/katzenpost/courier/server/config"
	replicacfg "github.com/katzenpost/katzenpost/replica/config"
	servercfg "github.com/katzenpost/katzenpost/server/config"
)

// validator pairs a component's production loader with a constructor of
// a fresh, empty Config of that component's type. The loader answers
// "is this a semantically valid config?" by reusing the very code the
// daemon runs at startup (reusing the real loader is deliberate: a
// reimplemented schema would drift and validate against a fiction). The
// fresh constructor feeds tomlstrict, which answers the orthogonal
// "does the file contain any key the schema does not recognise?".
type validator struct {
	load  func(path string) error
	fresh func() interface{}
}

// validators maps a component type name to its validator. The thin
// client has no fresh constructor: its own LoadFile already performs
// the strict unknown-key check, so layering tomlstrict on top would be
// redundant.
var validators = map[string]validator{
	"authority": {func(p string) error { _, err := authcfg.LoadFile(p, false); return err }, func() interface{} { return new(authcfg.Config) }},
	"server":    {func(p string) error { _, err := servercfg.LoadFile(p); return err }, func() interface{} { return new(servercfg.Config) }},
	"replica":   {func(p string) error { _, err := replicacfg.LoadFile(p, false); return err }, func() interface{} { return new(replicacfg.Config) }},
	"courier":   {func(p string) error { _, err := couriercfg.LoadFile(p); return err }, func() interface{} { return new(couriercfg.Config) }},
	"client":    {func(p string) error { _, err := clientcfg.LoadFile(p); return err }, func() interface{} { return new(clientcfg.Config) }},
	"thin":      {func(p string) error { _, err := thin.LoadFile(p); return err }, nil},
}

func knownTypes() string {
	return "authority, server, replica, courier, client, thin"
}

func newRootCommand() *cobra.Command {
	var compType string

	validateCmd := &cobra.Command{
		Use:   "validate --type <type> <file> [file...]",
		Short: "Validate one or more configuration files",
		Long: `Validate loads each given configuration file with the same loader the
corresponding daemon uses at startup, including its FixupAndValidate
pass, and reports the outcome per file. The process exits non-zero if
any file fails, which makes it suitable for CI and for a configs
Makefile target.

The component type is explicit rather than guessed from the filename:
deployment file names vary, and a validator that guesses would be a
validator that lies.

Component types:
  authority  directory authority (authority.toml)
  server     mix, gateway, and service nodes (katzenpost.toml)
  replica    pigeonhole storage replica (replica.toml)
  courier    pigeonhole courier (courier.toml)
  client     client daemon, kpclientd (client.toml)
  thin       thin client (thinclient.toml)`,
		Example: `  # Validate a single authority config
  kpconfig validate --type authority /etc/katzenpost/authority.toml

  # Validate every generated mix/gateway/service config
  kpconfig validate --type server configs/*-pq-mixserver.toml

  # Validate the thin client config
  kpconfig validate --type thin configs/thinclient.toml`,
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			v, ok := validators[compType]
			if !ok {
				return fmt.Errorf("unknown --type %q; known types: %s", compType, knownTypes())
			}
			failed := 0
			for _, path := range args {
				if err := v.load(path); err != nil {
					fmt.Fprintf(os.Stdout, "FAIL  %s: %v\n", path, err)
					failed++
					continue
				}
				if v.fresh != nil {
					if err := tomlstrict.Check(path, v.fresh()); err != nil {
						fmt.Fprintf(os.Stdout, "FAIL  %s: %v\n", path, err)
						failed++
						continue
					}
				}
				fmt.Fprintf(os.Stdout, "OK    %s\n", path)
			}
			if failed > 0 {
				fmt.Fprintf(os.Stdout, "\n%d of %d file(s) failed validation\n", failed, len(args))
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "\nall %d file(s) valid\n", len(args))
			return nil
		},
	}
	validateCmd.Flags().StringVar(&compType, "type", "",
		"component type, one of: "+knownTypes())
	validateCmd.MarkFlagRequired("type")

	rootCmd := &cobra.Command{
		Use:   "kpconfig",
		Short: "Katzenpost configuration validator",
		Long: `kpconfig validates Katzenpost component configuration files against the
same loaders the daemons use at startup. It is the umbrella counterpart
to each daemon's --validate-only flag: the flag guards a single node at
ExecStartPre time, kpconfig guards a whole directory of generated
configuration in CI before it ever reaches a node.`,
	}
	rootCmd.AddCommand(validateCmd)
	return rootCmd
}

func main() {
	common.ExecuteWithFang(newRootCommand())
}
