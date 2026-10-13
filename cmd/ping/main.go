// main.go - Katzenpost ping tool
// Copyright (C) 2018, 2019  David Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/rand"
	clientcommon "github.com/katzenpost/katzenpost/client/common"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/cmd/internal/mixclient"
	"github.com/katzenpost/katzenpost/common"
	"github.com/spf13/cobra"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

func randUser() string {
	user := [32]byte{}
	_, err := rand.Reader.Read(user[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", user[:])
}

// Config holds the command line configuration.
//
// The per-packet timeout is no longer an operator-tunable: the ping
// derives it from the consensus document's Mu parameter and the
// number of mix layers (see roundTripTimeout in ping.go). An
// operator-chosen value would either be too short (legitimate paths
// time out) or so long that lost packets stall the batch
// indefinitely, neither of which is helpful for a smoke-test tool.
type Config struct {
	ConfigFile     string
	Service        string
	Count          int
	Concurrency    int
	PrintDiff      bool
	ThinClientOnly bool
	LogLevel       string

	// RotateServices spreads the batch across every node offering the
	// requested service. Off by default so a plain ping keeps pinning a
	// single destination as it always has.
	RotateServices bool

	// Strict fails the run on any non-delivery, not only genuine mixnet loss.
	Strict bool
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Katzenpost mixnet ping tool",
		Long: `A ping tool for testing and debugging Katzenpost mixnet connectivity.

This ping tools sends Sphinx packets destined to the specified service but it's designed to
work with the "echo" mixnet service which replies with the same payload that it receives.
We measure the success rate of Sphinx packet delivery. This ping tool is a mixnet client
and thus supports both thin client mode by connecting to an existing kpclientd daemon and
full client mode where this ping tool starts it's own client daemon.`,
		Example: `  # Ping the echo service using thin client mode
  ping -c client.toml -s echo --thin

  # Ping with custom count and concurrency
  ping -c client.toml -s echo -n 10 -C 3

  # Show payload differences on mismatch
  ping -c client.toml -s echo --print-diff`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.Service == "" {
				return fmt.Errorf("must specify service name with -s/--service")
			}

			// Print log file location for user reference
			logPath := mixclient.LogFilePath("ping")
			if logPath != "" {
				fmt.Printf("Logging to: %s (level: %s)\n", logPath, cfg.LogLevel)
			}

			thinClient, daemon := mixclient.Connect(cfg.ConfigFile, cfg.ThinClientOnly, logPath, cfg.LogLevel)
			defer mixclient.Close(thinClient, daemon)

			mixclient.CloseOnInterrupt(thinClient, daemon)

			tally := executePing(thinClient, cfg.Service, cfg.Count, cfg.Concurrency, cfg.PrintDiff, cfg.RotateServices)
			return tally.gateError(cfg.Strict, cfg.Count)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "c", "", "configuration file")
	cmd.Flags().StringVarP(&cfg.Service, "service", "s", "echo", "service name")
	cmd.Flags().IntVarP(&cfg.Count, "count", "n", 5, "number of ping messages to send")
	cmd.Flags().IntVarP(&cfg.Concurrency, "concurrency", "C", 1, "number of concurrent ping operations")
	cmd.Flags().BoolVar(&cfg.PrintDiff, "print-diff", false, "print payload contents if reply is different than original")
	cmd.Flags().BoolVar(&cfg.RotateServices, "rotate-services", false, "spread the batch across every node offering the service, instead of pinning one")
	cmd.Flags().BoolVar(&cfg.Strict, "strict", false, "fail the run on any outcome short of delivery, not only genuine mixnet loss")
	cmd.Flags().BoolVar(&cfg.ThinClientOnly, "thin", false, "use thin client mode (connect to existing daemon)")
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", "DEBUG", "logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")

	// Mark required flags
	cmd.MarkFlagRequired("service")

	return cmd
}

// executePing performs the ping operation and returns the per-category counts.
//
// With rotate set the batch is spread across every node offering the service
// rather than pinned to one. That varies the destination hop, which otherwise
// sits on every route of a run and so cannot be told apart from the baseline.
func executePing(thinClient *thin.ThinClient, service string, count, concurrency int, printDiff, rotate bool) counts {
	var services []*clientcommon.ServiceDescriptor
	if rotate {
		var err error
		services, err = thinClient.GetServices(service)
		if err != nil {
			panic(err)
		}
	} else {
		desc, err := thinClient.GetService(service)
		if err != nil {
			panic(err)
		}
		services = []*clientcommon.ServiceDescriptor{desc}
	}

	return sendPings(thinClient, service, services, count, concurrency, printDiff)
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}
