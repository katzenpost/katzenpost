// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// voucher-router is the CBOR plugin that relays sealed contact vouchers
// from mixnet clients to pigeonhole services.
package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/op/go-logging.v1"

	kpcommon "github.com/katzenpost/katzenpost/common"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/plugin"
	"github.com/katzenpost/katzenpost/pigeonservice/router"
)

func main() {
	var (
		cfg          plugin.Config
		pollInterval time.Duration
		retention    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "voucher-router",
		Short: "Katzenpost voucher router plugin",
		Run: func(cmd *cobra.Command, args []string) {
			cfg.Name = "voucher_router"
			busy, err := ps.Marshal(&ps.RouterReply{Status: ps.StatusBusy})
			if err != nil {
				panic(err)
			}
			cfg.Busy = busy
			cfg.Start = func(ph ps.Pigeonhole, key *ps.PluginKey, log *logging.Logger) (plugin.Handler, func(), error) {
				r, err := router.New(router.Config{
					Key:          key,
					DBPath:       filepath.Join(cfg.DataDir, "voucher_router.db"),
					PollInterval: pollInterval,
					Retention:    retention,
					Log:          log,
				}, ph)
				if err != nil {
					return nil, nil, err
				}
				return r, func() { r.Close() }, nil
			}
			plugin.Run(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.LogDir, "log_dir", "", "logging directory")
	cmd.Flags().StringVar(&cfg.LogLevel, "log_level", "DEBUG", "logging level: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	cmd.Flags().StringVar(&cfg.DataDir, "data_dir", "", "directory holding the router's key and database")
	cmd.Flags().StringVar(&cfg.ThinConfig, "thin_config", "", "thin client config of the kpclientd to use")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", ps.DefaultPollInterval, "how often a pending Pigeonhole read is retried")
	cmd.Flags().DurationVar(&retention, "retention", 7*24*time.Hour, "how long a forwarded voucher is kept rewritten")
	cmd.SetArgs(kpcommon.NormalizeLegacyLongFlags(cmd, os.Args[1:], "log_dir", "log_level", "data_dir", "thin_config", "poll_interval"))
	kpcommon.ExecuteWithFang(cmd)
}
