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
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
	"github.com/katzenpost/katzenpost/pigeonservice/plugin"
)

func main() {
	var (
		cfg     plugin.Config
		refresh time.Duration
	)
	cmd := &cobra.Command{
		Use:   "service-directory",
		Short: "Katzenpost service directory plugin",
		Run: func(cmd *cobra.Command, args []string) {
			cfg.Name = "service_directory"
			busy, err := ps.Marshal(&ps.DirectoryReply{Status: ps.StatusBusy})
			if err != nil {
				panic(err)
			}
			cfg.Busy = busy
			cfg.Start = func(ph ps.Pigeonhole, key *ps.PluginKey, log *logging.Logger) (plugin.Handler, func(), error) {
				d, err := directory.New(directory.Config{
					Key:             key,
					DBPath:          filepath.Join(cfg.DataDir, "service_directory.db"),
					RefreshInterval: refresh,
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
	cmd.SetArgs(kpcommon.NormalizeLegacyLongFlags(cmd, os.Args[1:], "log_dir", "log_level", "data_dir", "thin_config"))
	kpcommon.ExecuteWithFang(cmd)
}
