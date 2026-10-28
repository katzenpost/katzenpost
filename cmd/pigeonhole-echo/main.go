// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// pigeonhole-echo is an example pigeonhole service: it echoes every message
// a client sends it.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
)

func main() {
	var (
		thinConfig   string
		dataDir      string
		logLevel     string
		pollInterval time.Duration
		maxSessions  int
	)
	cmd := &cobra.Command{
		Use:   "pigeonhole-echo",
		Short: "Example pigeonhole service that echoes what clients send",
		RunE: func(cmd *cobra.Command, args []string) error {
			logBackend, err := log.New("", logLevel, false)
			if err != nil {
				return err
			}
			cfg, err := thin.LoadFile(thinConfig)
			if err != nil {
				return err
			}
			c := thin.NewThinClient(cfg, &config.Logging{Level: logLevel})
			if err := c.Dial(); err != nil {
				return err
			}
			defer c.Close()
			ph := ps.NewThinPigeonhole(c)

			key, err := ps.LoadServiceKey(dataDir)
			if err != nil {
				return err
			}
			adv, err := directory.NewClient(ph, key, pollInterval)
			if err != nil {
				return err
			}
			svc, err := ps.NewService(ps.Config{
				Key:                   key,
				DataDir:               dataDir,
				DisplayName:           "echo",
				Advertiser:            adv,
				PollInterval:          pollInterval,
				MaxConcurrentSessions: maxSessions,
				Log:                   logBackend.GetLogger("echo"),
			}, ph)
			if err != nil {
				return err
			}
			defer svc.Close()
			id := svc.ID()
			fmt.Println(hex.EncodeToString(id[:]))

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
				for {
					msg, err := s.Recv(ctx)
					if err != nil {
						return
					}
					if err := s.Send(ctx, msg); err != nil {
						return
					}
				}
			}))
			if ctx.Err() != nil {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringVar(&thinConfig, "thin_config", "", "thin client config of the kpclientd to use")
	cmd.Flags().StringVar(&dataDir, "data_dir", "", "directory holding the service's key and state")
	cmd.Flags().StringVar(&logLevel, "log_level", "INFO", "logging level")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", ps.DefaultPollInterval, "how often a pending read is retried")
	cmd.Flags().IntVar(&maxSessions, "max_sessions", 64, "most sessions served at once")
	kpcommon.ExecuteWithFang(cmd)
}
