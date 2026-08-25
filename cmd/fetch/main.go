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
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile   string
	LogLevel     string
	MinReplicas  int
	RequireReady bool
	ReadyTimeout time.Duration
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
• Optionally waits for the whole testnet (mixes, replicas, couriers)
  to report ready on their metrics endpoints (--require-ready)

The tool is useful for network monitoring, debugging connectivity issues,
and inspecting the current state of the mixnet topology.`,
		Example: `  # Fetch network document with default settings
  fetch --config thinclient.toml

  # Fetch with short flags
  fetch -f thinclient.toml

  # Wait until the entire testnet reports ready before printing
  fetch -f /mixnet-alpine/client/thinclient-bridge.toml -r 2 --require-ready`,
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
	cmd.Flags().BoolVar(&cfg.RequireReady, "require-ready", false,
		"wait until every mix, storage replica, and courier reports ready on its metrics endpoint before printing the document")
	cmd.Flags().DurationVar(&cfg.ReadyTimeout, "ready-timeout", 8*time.Minute,
		"maximum time to wait for the whole network to report ready before failing with per-node diagnostics")

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
	logger := client.GetLogger("fetch")

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

	// Try the daemon's current signed document straight away. Under
	// --require-ready the waitForReady gate re-checks the live readiness
	// gauges against the current expected epochs on every poll, so this
	// document only supplies the node inventory; using the daemon's
	// current (possibly previous-epoch) document does not weaken the
	// gate. Dial() consumes the connect-time document without forwarding
	// it to the event sink, so skipping this shortcut would otherwise
	// stall readiness checks until the daemon's next PKI broadcast at the
	// next epoch boundary.
	if doc, err := fetchSignedDocument(client, 0); err == nil && hasEnoughReplicas(doc, cfg.MinReplicas) {
		if err := waitForReady(cfg, logger, doc); err != nil {
			return err
		}
		printDocument(doc, signerNames)
		return nil
	}

	if cfg.RequireReady {
		return waitRequireReady(client, logger, cfg, signerNames)
	}
	return waitForDocument(client, logger, cfg, signerNames)
}

// waitRequireReady polls the daemon's current signed document until one is
// available, then waits for the whole network to report ready and prints it.
//
// It deliberately registers NO broadcast event sink. The thin client's fan-out
// worker delivers every event to every registered sink in turn, blocking on a
// full one; while this goroutine is blocked inside GetPKIDocumentRaw waiting
// for its reply, its own persistent sink would accumulate events and, once
// full, stall that very reply (deadlock). Polling the current document every
// couple of seconds is strictly more reliable than the broadcast arm: the
// daemon always answers GetPKIDocument, whether from its cache or with an
// error reply, so there is no "broadcast only" case to wait for.
//
// Progress is reported on stdout from the very first poll, including the
// reason the wait cannot yet finish. A cold-start wait (which can run for
// minutes before the first consensus exists or it carries enough storage
// replicas) would otherwise be silent.
func waitRequireReady(client *thin.ThinClient, logger *logging.Logger, cfg Config, signerNames map[[32]byte]string) error {
	start := time.Now()
	fmt.Printf("waiting for the network to report ready (up to %v)...\n", cfg.ReadyTimeout)
	lastProgressLog := time.Now()
	for {
		doc, err := fetchSignedDocument(client, 0)
		if err == nil && hasEnoughReplicas(doc, cfg.MinReplicas) {
			if err := waitForReady(cfg, logger, doc); err != nil {
				return err
			}
			printDocument(doc, signerNames)
			return nil
		}
		if time.Since(lastProgressLog) >= 4*time.Second {
			reason := err
			if reason == nil {
				reason = fmt.Errorf("consensus has %d storage replica(s); need %d",
					len(doc.StorageReplicas), cfg.MinReplicas)
			}
			fmt.Printf("  still waiting for the network to report ready: %v (elapsed %v)\n",
				reason, time.Since(start).Round(time.Second))
			lastProgressLog = time.Now()
		}
		select {
		case <-client.HaltCh():
			return fmt.Errorf("connection closed before receiving PKI document")
		case <-time.After(2 * time.Second):
		}
	}
}

// waitForDocument waits, via the event sink, for a consensus that satisfies
// the replica requirement, then fetches and prints its signed form for that
// epoch. Used when --require-ready is off.
func waitForDocument(client *thin.ThinClient, logger *logging.Logger, cfg Config, signerNames map[[32]byte]string) error {
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
			doc, err := fetchSignedDocument(client, docEvent.Document.Epoch)
			if err != nil {
				return err
			}
			if err := waitForReady(cfg, logger, doc); err != nil {
				return err
			}
			printDocument(doc, signerNames)
			return nil
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

// fetchSignedDocument retrieves and parses the raw, signed PKI document for the
// given epoch (0 for the daemon's current epoch).
//
// Unlike the stripped document the daemon pushes by default, the raw payload
// retains every detached directory authority signature, whose fingerprints we
// map to names. The daemon has already verified the signatures as a condition
// of accepting the consensus, so fetch does not re-verify them; it only labels
// each signer.
func fetchSignedDocument(client *thin.ThinClient, epoch uint64) (*cpki.Document, error) {
	raw, gotEpoch, err := client.GetPKIDocumentRaw(epoch)
	if err != nil {
		if epoch == 0 && gotEpoch != 0 {
			// A reply carrying an epoch means the daemon answered the
			// "current document" request at all, and its only error reply
			// for one is "no document cached". That is the normal
			// cold-start case, so say so plainly instead of echoing a
			// cryptic protocol error.
			now, _, till := epochtime.Now()
			return nil, fmt.Errorf("no consensus document for current epoch %d; next epoch %d starts in ~%v",
				now, now+1, till.Round(time.Second))
		}
		return nil, fmt.Errorf("failed to fetch raw PKI document for epoch %d: %v", epoch, err)
	}

	doc, err := cpki.ParseDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw PKI document for epoch %d: %v", gotEpoch, err)
	}
	return doc, nil
}

// printDocument prints the document followed by the directory authorities that
// signed it, by name where the fingerprint is known and by fingerprint otherwise.
func printDocument(doc *cpki.Document, signerNames map[[32]byte]string) {
	fmt.Printf("%v", doc)
	printSigners(doc, doc.Epoch, signerNames)
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

// probe describes one node whose metrics endpoint we poll for readiness.
type probe struct {
	name  string
	kind  string // "mix", "replica", "courier"
	addr  string
	ready string
	epoch string
}

// waitForReady blocks until every node in the document reports ready on its
// metrics endpoint (--require-ready only). The fetched document supplies the
// node inventory; the expected epochs are recomputed each poll so a mid-wait
// epoch rotation does not wedge the loop. While waiting, every 4 seconds (two
// polls) the current ready/waiting split is logged at DEBUG.
func waitForReady(cfg Config, logger *logging.Logger, doc *cpki.Document) error {
	if !cfg.RequireReady {
		return nil
	}
	probes, err := discoverProbes(cfg.ConfigFile, doc)
	if err != nil {
		return err
	}
	fmt.Printf("waiting for the network to report ready (%d node(s), up to %v)...\n", len(probes), cfg.ReadyTimeout)
	deadline := time.Now().Add(cfg.ReadyTimeout)
	lastProgressLog := time.Now()
	for {
		notReady := checkProbes(probes)
		if len(notReady) == 0 {
			fmt.Printf("network ready: all %d node(s) report ready\n", len(probes))
			return nil
		}
		if time.Now().After(deadline) {
			printNotReady(probes, notReady)
			return fmt.Errorf("timed out after %v waiting for the network to report ready (%d node(s) not ready)", cfg.ReadyTimeout, len(notReady))
		}
		if time.Since(lastProgressLog) >= 4*time.Second {
			ready, waiting := readyWaitingNames(probes, notReady)
			logger.Debugf("ready %d/%d node(s): ready=[%s] waiting=[%s]",
				len(ready), len(probes), strings.Join(ready, ","), strings.Join(waiting, ","))
			lastProgressLog = time.Now()
		}
		time.Sleep(2 * time.Second)
	}
}

// probeReport records why a single probe is not ready.
type probeReport struct {
	probe    *probe
	err      error
	ready    bool
	epoch    float64
	expected uint64
}

// checkProbes returns a report for every node that is not currently ready.
func checkProbes(probes []*probe) []probeReport {
	var notReady []probeReport
	for _, p := range probes {
		var expected uint64
		switch p.kind {
		case "replica":
			expected, _, _ = replicaCommon.ReplicaNow()
		default:
			expected, _, _ = epochtime.Now()
		}
		r, err := scrapeGauge(p.addr, p.ready)
		if err != nil {
			notReady = append(notReady, probeReport{probe: p, err: err})
			continue
		}
		e, err := scrapeGauge(p.addr, p.epoch)
		if err != nil {
			notReady = append(notReady, probeReport{probe: p, err: err})
			continue
		}
		if r != 1 || uint64(e) != expected {
			notReady = append(notReady, probeReport{probe: p, ready: r == 1, epoch: e, expected: expected})
		}
	}
	return notReady
}

// readyWaitingNames splits the probe inventory into the names currently
// reporting ready and those still waiting, preserving probe order.
func readyWaitingNames(probes []*probe, notReady []probeReport) (ready, waiting []string) {
	waitingSet := make(map[string]bool, len(notReady))
	for _, r := range notReady {
		waitingSet[r.probe.name] = true
	}
	for _, p := range probes {
		if waitingSet[p.name] {
			waiting = append(waiting, p.name)
		} else {
			ready = append(ready, p.name)
		}
	}
	return ready, waiting
}

// printNotReady emits per-node diagnostics for every unready node.
func printNotReady(probes []*probe, reports []probeReport) {
	ready, waiting := readyWaitingNames(probes, reports)
	fmt.Fprintf(os.Stderr, "network NOT ready: %d of %d node(s) ready: [%s]; still waiting on %d node(s): [%s]\n",
		len(ready), len(probes), strings.Join(ready, ","), len(waiting), strings.Join(waiting, ","))
	for _, r := range reports {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "  %-24s %-9s %-20s error: %v\n", r.probe.name, r.probe.kind, r.probe.addr, r.err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-24s %-9s %-20s ready=%v epoch=%d expected=%d\n",
			r.probe.name, r.probe.kind, r.probe.addr, r.ready, uint64(r.epoch), r.expected)
	}
}

// scrapeGauge fetches a single metric line from the node's /metrics endpoint.
func scrapeGauge(addr, name string) (float64, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == name {
			return strconv.ParseFloat(fields[1], 64)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("metric %q not present on %s", name, addr)
}

// discoverProbes builds the readiness probe list from the consensus document
// and the testnet config layout rooted next to the thin client config file.
func discoverProbes(configFile string, doc *cpki.Document) ([]*probe, error) {
	netRoot := filepath.Dir(filepath.Dir(configFile))
	var probes []*probe
	seen := make(map[string]bool)
	add := func(p *probe) {
		if p == nil || seen[p.addr] {
			return
		}
		seen[p.addr] = true
		probes = append(probes, p)
	}

	for _, desc := range doc.GatewayNodes {
		p, err := serverProbe(netRoot, desc)
		if err != nil {
			return nil, err
		}
		add(p)
		cs, err := courierProbes(netRoot, desc)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			add(c)
		}
	}
	for _, desc := range doc.ServiceNodes {
		p, err := serverProbe(netRoot, desc)
		if err != nil {
			return nil, err
		}
		add(p)
		cs, err := courierProbes(netRoot, desc)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			add(c)
		}
	}
	for _, layer := range doc.Topology {
		for _, desc := range layer {
			p, err := serverProbe(netRoot, desc)
			if err != nil {
				return nil, err
			}
			add(p)
		}
	}
	for _, desc := range doc.StorageReplicas {
		addr, err := metricsAddrFromFile(filepath.Join(netRoot, desc.Name, "replica.toml"), "MetricsAddress")
		if err != nil {
			return nil, fmt.Errorf("replica %q: %w", desc.Name, err)
		}
		add(&probe{name: desc.Name, kind: "replica", addr: addr,
			ready: "katzenpost_replica_ready", epoch: "katzenpost_replica_current_epoch"})
	}
	return probes, nil
}

// serverProbe discovers the [Server] MetricsAddress for a mix node.
func serverProbe(netRoot string, desc *cpki.MixDescriptor) (*probe, error) {
	addr, err := metricsAddrFromFile(filepath.Join(netRoot, desc.Name, "katzenpost.toml"), "Server.MetricsAddress")
	if err != nil {
		return nil, fmt.Errorf("mix %q: %w", desc.Name, err)
	}
	return &probe{name: desc.Name, kind: "mix", addr: addr,
		ready: "katzenpost_node_ready", epoch: "katzenpost_node_current_epoch"}, nil
}

// courierProbes discovers the metrics endpoint of every courier plugin
// declared in a service node's katzenpost.toml. A service node with no
// courier plugin yields no probes; a declared courier whose config cannot be
// read is an error.
func courierProbes(netRoot string, desc *cpki.MixDescriptor) ([]*probe, error) {
	cfgPath := filepath.Join(netRoot, desc.Name, "katzenpost.toml")
	var c struct {
		ServiceNode struct {
			CBORPluginKaetzchen []struct {
				Capability string `toml:"Capability"`
				Config     struct {
					C string `toml:"c"`
				} `toml:"Config"`
			} `toml:"CBORPluginKaetzchen"`
		} `toml:"ServiceNode"`
	}
	if _, err := toml.DecodeFile(cfgPath, &c); err != nil {
		return nil, fmt.Errorf("service node %q: parse %q: %w", desc.Name, cfgPath, err)
	}
	var probes []*probe
	for _, k := range c.ServiceNode.CBORPluginKaetzchen {
		if !strings.Contains(strings.ToLower(k.Capability), "courier") {
			continue
		}
		if k.Config.C == "" {
			continue
		}
		courierCfg := resolveNetPath(netRoot, k.Config.C)
		addr, err := metricsAddrFromFile(courierCfg, "MetricsAddress")
		if err != nil {
			return nil, fmt.Errorf("courier of %q: %w", desc.Name, err)
		}
		probes = append(probes, &probe{name: desc.Name, kind: "courier", addr: addr,
			ready: "katzenpost_courier_ready", epoch: "katzenpost_courier_current_epoch"})
	}
	return probes, nil
}

// resolveNetPath maps a kaetzchen plugin config path to a readable location.
// Generated testnet configs bake in the container-absolute mount path (e.g.
// /mixnet-alpine/...); when that does not exist on the local filesystem,
// rebase it onto the testnet root derived from the thin client config file.
func resolveNetPath(netRoot, p string) string {
	if !filepath.IsAbs(p) {
		return filepath.Join(netRoot, p)
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if base := filepath.Base(netRoot); strings.HasPrefix(p, "/"+base+"/") {
		return filepath.Join(netRoot, strings.TrimPrefix(p, "/"+base))
	}
	return p
}

// metricsAddrFromFile extracts a metrics address from a TOML config. The key
// is either "MetricsAddress" (top-level) or "Server.MetricsAddress".
func metricsAddrFromFile(path, key string) (string, error) {
	var c struct {
		Server struct {
			MetricsAddress string `toml:"MetricsAddress"`
		} `toml:"Server"`
		MetricsAddress string `toml:"MetricsAddress"`
	}
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return "", fmt.Errorf("parse %q: %w", path, err)
	}
	switch key {
	case "Server.MetricsAddress":
		if c.Server.MetricsAddress == "" {
			return "", fmt.Errorf("%q: missing [Server] MetricsAddress", path)
		}
		return c.Server.MetricsAddress, nil
	default:
		if c.MetricsAddress == "" {
			return "", fmt.Errorf("%q: missing MetricsAddress", path)
		}
		return c.MetricsAddress, nil
	}
}
