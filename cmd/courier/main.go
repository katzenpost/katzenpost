// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/common/tomlstrict"
	"github.com/katzenpost/katzenpost/courier/server"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type courierConfig struct {
	configFile   string
	validateOnly bool
}

func newRootCommand() *cobra.Command {
	var cfg courierConfig
	cmd := &cobra.Command{
		Use:   "courier",
		Short: "Katzenpost storage courier service",
		Run: func(cmd *cobra.Command, args []string) {
			runCourier(cfg)
		},
	}

	cmd.Flags().StringVarP(&cfg.configFile, "config", "c", "", "configuration file")
	cmd.Flags().BoolVar(&cfg.validateOnly, "validate-only", false,
		"load and validate the configuration file, then exit without side effects")
	return cmd
}

func main() {
	cmd := newRootCommand()
	cmd.SetArgs(normalizeLegacyArgs(cmd, os.Args[1:]))
	kpcommon.ExecuteWithFang(cmd)
}

func normalizeLegacyArgs(cmd *cobra.Command, args []string) []string {
	return kpcommon.NormalizeLegacyLongFlags(cmd, args, "validate-only")
}

func runCourier(cmdCfg courierConfig) {
	cfg, err := config.LoadFile(cmdCfg.configFile)
	if err != nil {
		if cmdCfg.validateOnly {
			fmt.Fprintf(os.Stderr, "configuration file '%v' is invalid: %v\n", cmdCfg.configFile, err)
			os.Exit(1)
		}
		cborplugin.FailStartup("courier", err)
	}
	if cmdCfg.validateOnly {
		if err := tomlstrict.Check(cmdCfg.configFile, new(config.Config)); err != nil {
			fmt.Fprintf(os.Stderr, "configuration file '%v' is invalid: %v\n", cmdCfg.configFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "configuration file '%v' is valid\n", cmdCfg.configFile)
		os.Exit(0)
	}

	s, err := server.New(cfg, nil)
	if err != nil {
		cborplugin.FailStartup("courier", err)
	}

	// blocks until service node disconnect
	s.StartPlugin()
}
