// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// pigeonhole-voucher lists the pigeonhole services in the service directory,
// and sends a pigeonhole service a voucher token that a chat app minted, so
// that the service inducts the app.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	kpcommon "github.com/katzenpost/katzenpost/common"
	ps "github.com/katzenpost/katzenpost/pigeonservice"
	"github.com/katzenpost/katzenpost/pigeonservice/directory"
)

// list writes each service in the directory: its ID and how many routers it is reachable through.
func list(ctx context.Context, dir *directory.All, w io.Writer) error {
	descs, err := dir.List(ctx)
	if err != nil {
		return err
	}
	for _, d := range descs {
		id := d.ID()
		fmt.Fprintf(w, "%s %d routers\n", hex.EncodeToString(id[:]), len(d.Routers))
	}
	return nil
}

// send routes the voucher token, in base64, to the pigeonhole service with the given identity, in hex.
func send(ctx context.Context, ph ps.Pigeonhole, dir *directory.All, serviceID, code string) error {
	raw, err := hex.DecodeString(serviceID)
	if err != nil || len(raw) != len(ps.ServiceID{}) {
		return errors.New("a service identity is 64 hex digits")
	}
	voucher, err := base64.StdEncoding.DecodeString(strings.TrimSpace(code))
	if err != nil || len(voucher) == 0 {
		return errors.New("a voucher token is base64")
	}
	d, err := dir.Lookup(ctx, ps.ServiceID(raw))
	if err != nil {
		return fmt.Errorf("looking up the service: %w", err)
	}
	return ps.Route(ctx, ph, d, voucher)
}

func main() {
	var (
		thinConfig   string
		logLevel     string
		pollInterval time.Duration
	)
	// run connects to kpclientd and calls f with the directories the PKI lists.
	run := func(f func(ctx context.Context, ph ps.Pigeonhole, dir *directory.All) error) error {
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
		dir, err := directory.NewAll(ph, nil, pollInterval)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return f(ctx, ph, dir)
	}
	cmd := &cobra.Command{
		Use:   "pigeonhole-voucher",
		Short: "Find pigeonhole services and send them voucher tokens",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the services in the service directory",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return run(func(ctx context.Context, _ ps.Pigeonhole, dir *directory.All) error {
				return list(ctx, dir, os.Stdout)
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "send SERVICE_IDENTITY VOUCHER_TOKEN",
		Short: "Route a voucher token your chat app minted to the pigeonhole service with that identity, which then inducts the app",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return run(func(ctx context.Context, ph ps.Pigeonhole, dir *directory.All) error {
				if err := send(ctx, ph, dir, args[0], args[1]); err != nil {
					return err
				}
				fmt.Println("a router accepted the voucher token; the service will induct it")
				return nil
			})
		},
	})
	cmd.PersistentFlags().StringVar(&thinConfig, "thin_config", "", "thin client config of the kpclientd to use")
	cmd.PersistentFlags().StringVar(&logLevel, "log_level", "ERROR", "logging level")
	cmd.PersistentFlags().DurationVar(&pollInterval, "poll_interval", ps.DefaultPollInterval, "how often a pending read is retried")
	kpcommon.ExecuteWithFang(cmd)
}
