// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// pigeonhole-dial connects to a pigeonhole service found in the service
// directory, sends it each line of standard input, and prints what it
// sends back.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	kpcommon "github.com/katzenpost/katzenpost/common"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
)

func main() {
	var (
		thinConfig   string
		logLevel     string
		name         string
		pollInterval time.Duration
		list         bool
	)
	cmd := &cobra.Command{
		Use:   "pigeonhole-dial [service ID]",
		Short: "Talk to a pigeonhole service",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			dir, err := directory.NewClient(ph, nil, pollInterval)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if list {
				descs, err := dir.List(ctx)
				if err != nil {
					return err
				}
				for _, d := range descs {
					id := d.ID()
					fmt.Printf("%s %d routers\n", hex.EncodeToString(id[:]), len(d.Routers))
				}
				return nil
			}
			if len(args) != 1 {
				return errors.New("give a service ID, or --list")
			}
			raw, err := hex.DecodeString(args[0])
			if err != nil || len(raw) != 32 {
				return errors.New("a service ID is 64 hex digits")
			}
			d, err := dir.Lookup(ctx, ps.ServiceID(raw))
			if err != nil {
				return err
			}
			conn, err := ps.Dial(ctx, ph, d, name, pollInterval)
			if err != nil {
				return err
			}
			lines := bufio.NewScanner(os.Stdin)
			for lines.Scan() {
				if len(lines.Bytes()) == 0 {
					continue
				}
				if err := conn.Send(ctx, lines.Bytes()); err != nil {
					return err
				}
				reply, err := conn.Recv(ctx)
				if err != nil {
					return err
				}
				fmt.Println(string(reply))
			}
			return lines.Err()
		},
	}
	cmd.Flags().StringVar(&thinConfig, "thin_config", "", "thin client config of the kpclientd to use")
	cmd.Flags().StringVar(&logLevel, "log_level", "ERROR", "logging level")
	cmd.Flags().StringVar(&name, "name", "client", "display name given to the service")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", ps.DefaultPollInterval, "how often a pending read is retried")
	cmd.Flags().BoolVar(&list, "list", false, "list the services in the directory")
	kpcommon.ExecuteWithFang(cmd)
}
