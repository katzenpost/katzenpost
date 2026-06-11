// main.go - Katzenpost
// Copyright (C) 2017  Yawning Angel.
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
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/common"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile  string
	LogLevel    string
	MinReplicas int
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch network documents from Katzenpost directory authorities",
		Long: `Fetch and display network topology documents from Katzenpost directory
authorities. This tool connects to the client daemon to retrieve the
current network consensus document containing mix node information.

Core functionality:
• Connects to client daemon using thin client configuration
• Retrieves current network consensus documents
• Displays network topology and mix node information
• Retries until PKI document becomes available

The tool is useful for network monitoring, debugging connectivity issues,
and inspecting the current state of the mixnet topology.`,
		Example: `  # Fetch network document with default settings
  fetch --config thinclient.toml

  # Fetch with short flags
  fetch -f thinclient.toml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFetch(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "f", "thinclient.toml",
		"path to the thin client configuration file (TOML format)")
	cmd.Flags().StringVarP(&cfg.LogLevel, "log_level", "l", "DEBUG",
		"logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")
	cmd.Flags().IntVarP(&cfg.MinReplicas, "min-replicas", "r", 0,
		"keep waiting for further consensus documents until at least N storage replicas are present (0 = no requirement)")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runFetch fetches network documents from directory authorities
func runFetch(cfg Config) error {
	thinCfg, err := thin.LoadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}

	logging := &config.Logging{
		Level: cfg.LogLevel,
	}
	client := thin.NewThinClient(thinCfg, logging)

	// Ensure thin_close is sent even on Ctrl-C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		client.Close()
		os.Exit(0)
	}()
	defer client.Close()

	// Connect to the daemon
	err = client.Dial()
	if err != nil {
		return fmt.Errorf("failed to connect to client daemon: %v", err)
	}

	if doc := client.PKIDocument(); doc != nil && hasEnoughReplicas(doc, cfg.MinReplicas) {
		return printRawDocument(client, doc.Epoch)
	}

	// Wait for PKI document via event sink
	eventSink := client.EventSink()
	defer client.StopEventSink(eventSink)

	for {
		select {
		case event := <-eventSink:
			docEvent, ok := event.(*thin.NewDocumentEvent)
			if !ok {
				continue
			}
			if !hasEnoughReplicas(docEvent.Document, cfg.MinReplicas) {
				continue
			}
			return printRawDocument(client, docEvent.Document.Epoch)
		case <-client.HaltCh():
			return fmt.Errorf("connection closed before receiving PKI document")
		}
	}
}

// printRawDocument fetches the raw, signed PKI document for the given epoch
// and prints both the document and the directory authorities that signed it.
//
// Unlike the stripped document the daemon pushes by default, the raw payload
// retains every detached directory authority signature, so we may report the
// identity-key fingerprint of each signer.
func printRawDocument(client *thin.ThinClient, epoch uint64) error {
	raw, gotEpoch, err := client.GetPKIDocumentRaw(epoch)
	if err != nil {
		return fmt.Errorf("failed to fetch raw PKI document for epoch %d: %v", epoch, err)
	}

	doc, err := cpki.ParseDocument(raw)
	if err != nil {
		return fmt.Errorf("failed to parse raw PKI document for epoch %d: %v", gotEpoch, err)
	}

	fmt.Printf("%v", doc)
	printSigners(doc, gotEpoch)
	return nil
}

// printSigners reports, in deterministic order, the identity-key fingerprint of
// every directory authority that signed the document. The thin client config
// carries no dirauth peer list, so we have nothing finer than the fingerprint
// (the 256-bit hash of the signer's identity public key) to identify them by.
func printSigners(doc *cpki.Document, epoch uint64) {
	fingerprints := make([]string, 0, len(doc.Signatures))
	for hash := range doc.Signatures {
		fingerprints = append(fingerprints, fmt.Sprintf("%x", hash[:]))
	}
	sort.Strings(fingerprints)

	fmt.Printf("\nPKI document for epoch %d signed by %d directory %s:\n",
		epoch, len(fingerprints), authorityWord(len(fingerprints)))
	for _, fp := range fingerprints {
		fmt.Printf("  %s\n", fp)
	}
}

// authorityWord yields the singular or plural noun so the surrounding sentence
// reads "1 directory authority" but "3 directory authorities".
func authorityWord(n int) string {
	if n == 1 {
		return "authority"
	}
	return "authorities"
}

// hasEnoughReplicas reports whether the given document satisfies the caller's
// minimum replica requirement. A min of 0 imposes no constraint.
func hasEnoughReplicas(doc *cpki.Document, min int) bool {
	if min <= 0 {
		return true
	}
	return doc != nil && len(doc.StorageReplicas) >= min
}
