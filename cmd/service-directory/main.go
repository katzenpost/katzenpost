// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// service-directory is the CBOR plugin holding the descriptors pigeonhole
// services advertise.
package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/op/go-logging.v1"

	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/plugin"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
)

func main() {
	var (
		cfg        plugin.Config
		refresh    time.Duration
		maxEntries int
	)
	cmd := &cobra.Command{
		Use:   "service-directory",
		Short: "Katzenpost service directory plugin",
		Run: func(cmd *cobra.Command, args []string) {
			cfg.Name = "service_directory"
			busy, err := common.Marshal(&discovery.DirectoryReply{Status: common.StatusBusy})
			if err != nil {
				panic(err)
			}
			cfg.Busy = busy
			cfg.Start = func(ph common.Pigeonhole, key *common.PluginKey, log *logging.Logger) (plugin.Handler, func(), error) {
				d, err := discovery.New(discovery.Config{
					Key:             key,
					DBPath:          filepath.Join(cfg.DataDir, "service_directory.db"),
					RefreshInterval: refresh,
					MaxEntries:      maxEntries,
					Log:             log,
				}, ph)
				if err != nil {
					return nil, nil, err
				}
				return d, func() { d.Close() }, nil
			}
			plugin.Run(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.LogDir, "log_dir", "", "logging directory")
	cmd.Flags().StringVar(&cfg.LogLevel, "log_level", "DEBUG", "logging level: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	cmd.Flags().StringVar(&cfg.DataDir, "data_dir", "", "directory holding the directory's key and database")
	cmd.Flags().StringVar(&cfg.ThinConfig, "thin_config", "", "thin client config of the kpclientd to use")
	cmd.Flags().DurationVar(&refresh, "refresh", 24*time.Hour, "longest a snapshot goes unrewritten")
	cmd.Flags().IntVar(&maxEntries, "max_entries", discovery.DefaultMaxEntries, "most services listed at once")
	cmd.SetArgs(kpcommon.NormalizeLegacyLongFlags(cmd, os.Args[1:], "log_dir", "log_level", "data_dir", "thin_config", "max_entries"))
	kpcommon.ExecuteWithFang(cmd)
}
