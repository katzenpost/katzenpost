// SPDX-License-Identifier: AGPL-3.0-only

package mixclient

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// perHopSlopMs is the wall-clock budget per Sphinx hop on top of the
// encoded per-hop delay. It covers crypto unwrap, scheduler dwell, and
// network transmission between adjacent nodes. 500ms is comfortably
// above the server's default SchedulerSlack (450ms) plus typical
// crypto/network overhead, and the budget multiplies by the hop count
// so a longer topology gets proportionally more slack.
const perHopSlopMs uint64 = 500

// fallbackRoundTrip is the timeout used when the PKI document is not
// yet available. It is well above any honest path's RTT and well below
// the one-epoch SURB validity window, so the ping cannot block
// indefinitely waiting for a doc.
const fallbackRoundTrip = 60 * time.Second

// roundTripTimeout returns the per-packet timeout derived from the
// consensus document's Mu parameter and topology. Per-hop delays are
// drawn from Exp(Mu) and clamped at common.SafetyCap(Mu) (the
// 1 - 10^-12 quantile), so the encoded Sphinx round-trip delay is
// strictly bounded above by hops × SafetyCap(Mu). We add a per-hop
// slop budget for processing and network overhead. The result is a
// timeout that effectively never false-positives on an honest path
// and which cuts off lost packets in tens of seconds rather than
// blocking the batch forever.
//
// The hop count for an echo round-trip is 2L + 3 where L is the
// number of mix layers: forward path is gateway + L mixes + service
// (L + 2 hops with encoded delays because the packet carries a SURB),
// SURB return is L mixes + gateway (L + 1 hops). For the default
// L = 3 topology this is 9, matching the paper's Erlang-9 analysis.
// ReplySlop is how long past the daemon's own estimate of a reply's due time
// a packet is worth waiting for.
//
// The daemon reports, as ReplyETA, the delay actually encoded into the packet
// it just sent. What that figure cannot include is the wall-clock cost the
// Sphinx delays do not encode: crypto at each hop, scheduler dwell, and
// transmission between nodes. Those are what this budget covers, at
// perHopSlopMs each.
//
// The alternative, which this replaces as the normal case, is to wait
// roundTripTimeout for every packet. That bound assumes every hop drew close
// to the worst delay the distribution permits, which on namenlos comes to four
// minutes; a packet that is simply lost then holds a concurrency slot for four
// minutes rather than the few seconds its own route warranted.
func ReplySlop(doc *cpki.Document) time.Duration {
	hops := uint64(9)
	if doc != nil && len(doc.Topology) > 0 {
		hops = uint64(2*len(doc.Topology) + 3)
	}
	return time.Duration(hops*perHopSlopMs) * time.Millisecond
}

// RoundTripTimeout returns the outer bound on a packet's wait, used when the
// daemon reports no estimate of its own: an older daemon, or a send that
// failed before the estimate arrived. See replySlop for the normal case.
func RoundTripTimeout(doc *cpki.Document) time.Duration {
	if doc == nil || doc.Mu <= 0 || len(doc.Topology) == 0 {
		return fallbackRoundTrip
	}
	hops := uint64(2*len(doc.Topology) + 3)
	perHopCapMs := kpcommon.SafetyCap(doc.Mu)
	if perHopCapMs == 0 {
		return fallbackRoundTrip
	}
	totalMs := hops * (perHopCapMs + perHopSlopMs)
	return time.Duration(totalMs) * time.Millisecond
}

func LogFilePath(tool string) string {
	tmpFile, err := os.CreateTemp("", tool+".log.*.tmp")
	if err != nil {
		// If we can't create a temp file, fall back to no logging
		return ""
	}

	// Get the file path and close the file (we just want the path)
	logPath := tmpFile.Name()
	tmpFile.Close()

	return logPath
}

// Connect sets up either thin client or full daemon mode
func Connect(configFile string, thinClientOnly bool, logPath string, logLevel string) (*thin.ThinClient, *client.Daemon) {
	if thinClientOnly {
		return initializeThinClient(configFile, logPath, logLevel), nil
	}
	return initializeFullClient(configFile, logPath, logLevel)
}

// initializeThinClient sets up thin client mode
func initializeThinClient(configFile string, logPath string, logLevel string) *thin.ThinClient {
	cfg, err := thin.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open thin client config: %s", err))
	}

	logging := &config.Logging{
		Disable: false,
		File:    logPath,
		Level:   logLevel,
	}

	thinClient := thin.NewThinClient(cfg, logging)
	err = thinClient.Dial()
	if err != nil {
		panic(fmt.Errorf("failed to connect to daemon: %s", err))
	}
	return thinClient
}

// initializeFullClient sets up full daemon mode
func loadFullConfig(configFile string) (*config.Config, error) {
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config: %s", err)
	}
	if err := epochtime.Configure(cfg.EpochDuration, os.Stderr); err != nil {
		return nil, fmt.Errorf("config file '%v': %v", configFile, err)
	}
	return cfg, nil
}

func initializeFullClient(configFile string, logPath string, logLevel string) (*thin.ThinClient, *client.Daemon) {
	cfg, err := loadFullConfig(configFile)
	if err != nil {
		panic(err)
	}

	// Override logging configuration to use our log file
	if cfg.Logging == nil {
		cfg.Logging = &config.Logging{}
	}
	cfg.Logging.File = logPath
	cfg.Logging.Level = logLevel
	cfg.Logging.Disable = false

	// create a client and connect to the mixnet Gateway
	daemon, err := client.NewDaemon(cfg)
	if err != nil {
		panic(err)
	}
	err = daemon.Start()
	if err != nil {
		panic(err)
	}

	fmt.Println("Sleeping for 3 seconds to let the client daemon startup...")
	time.Sleep(time.Second * 3)

	thinClient := thin.NewThinClient(thin.FromConfig(cfg), cfg.Logging)
	err = thinClient.Dial()
	if err != nil {
		panic(err)
	}
	return thinClient, daemon
}

// Close closes the thin client connection and shuts down the daemon if running
func Close(thinClient *thin.ThinClient, daemon *client.Daemon) {
	if thinClient != nil {
		thinClient.Close()
	}
	if daemon != nil {
		daemon.Shutdown()
	}
}

func CloseOnInterrupt(thinClient *thin.ThinClient, daemon *client.Daemon) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println()
		Close(thinClient, daemon)
		os.Exit(0)
	}()
}
