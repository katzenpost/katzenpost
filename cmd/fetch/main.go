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

	// Resolve the directory authority names once, so signers may be
	// reported by identifier rather than by opaque fingerprint.
	signerNames := loadAuthorityNames(client)

	if doc := client.PKIDocument(); doc != nil && hasEnoughReplicas(doc, cfg.MinReplicas) {
		return printRawDocument(client, doc.Epoch, signerNames)
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
			return printRawDocument(client, docEvent.Document.Epoch, signerNames)
		case <-client.HaltCh():
			return fmt.Errorf("connection closed before receiving PKI document")
		}
	}
}

// loadAuthorityNames asks the daemon for its directory authority descriptors
// and builds a map from each authority's identity-key fingerprint to its
// human-readable identifier. The fingerprint is the very value by which a PKI
// document's signatures are keyed, so this lets us name the signers.
//
// A failure here is not fatal: an older daemon may not support the request,
// in which case we note it and fall back to reporting bare fingerprints.
func loadAuthorityNames(client *thin.ThinClient) map[[32]byte]string {
	authorities, err := client.GetDirectoryAuthorities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: could not resolve directory authority names (%v); reporting fingerprints only\n", err)
		return nil
	}

	names := make(map[[32]byte]string, len(authorities))
	for _, auth := range authorities {
		names[auth.IdentityKeyHash] = auth.Identifier
	}
	return names
}

// printRawDocument fetches the raw, signed PKI document for the given epoch
// and prints both the document and the directory authorities that signed it.
//
// Unlike the stripped document the daemon pushes by default, the raw payload
// retains every detached directory authority signature, so we may report each
// signer, by name where the fingerprint is known and by fingerprint otherwise.
func printRawDocument(client *thin.ThinClient, epoch uint64, signerNames map[[32]byte]string) error {
	raw, gotEpoch, err := client.GetPKIDocumentRaw(epoch)
	if err != nil {
		return fmt.Errorf("failed to fetch raw PKI document for epoch %d: %v", epoch, err)
	}

	doc, err := cpki.ParseDocument(raw)
	if err != nil {
		return fmt.Errorf("failed to parse raw PKI document for epoch %d: %v", gotEpoch, err)
	}

	fmt.Printf("%v", doc)
	printSigners(doc, gotEpoch, signerNames)
	return nil
}

// printSigners reports, in deterministic order, every directory authority that
// signed the document. Each signer is named by its identifier where its
// fingerprint (the 256-bit hash of its identity public key) is known, with the
// fingerprint in parentheses; signers absent from signerNames are reported by
// fingerprint alone.
func printSigners(doc *cpki.Document, epoch uint64, signerNames map[[32]byte]string) {
	labels := make([]string, 0, len(doc.Signatures))
	for fp := range doc.Signatures {
		if name := signerNames[fp]; name != "" {
			labels = append(labels, fmt.Sprintf("%s (%x)", name, fp[:]))
		} else {
			labels = append(labels, fmt.Sprintf("%x", fp[:]))
		}
	}
	sort.Strings(labels)

	fmt.Printf("\nPKI document for epoch %d signed by %d directory %s:\n",
		epoch, len(labels), authorityWord(len(labels)))
	for _, label := range labels {
		fmt.Printf("  %s\n", label)
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
