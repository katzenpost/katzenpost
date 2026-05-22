// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"

	"github.com/katzenpost/katzenpost/common/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	defaultAddress           = ":3266"
	defaultOutgoingQueueSize = 64         // Default queue size for outgoing connections
	defaultKeepAliveInterval = 180 * 1000 // Default TCP keep-alive interval (3 minutes)

	// IncomingQueueSize, ProxyRequestTimeout and ProxyWorkerCount
	// intentionally have no fixed defaults here. Zero in the config
	// signals "auto-derive at server.New from runtime.NumCPU and the
	// startup CTIDH self-check"; see ApplyRuntimeDefaults below.

	// DefaultMinFreeStorageMiB is the default filesystem free-space
	// reserve, in mebibytes. By default the replica will use the
	// DataDir filesystem freely but stop accepting new writes once
	// fewer than this many MiB remain available, so a runaway write
	// rate cannot wedge the host on a full disk.
	DefaultMinFreeStorageMiB = 500
)

// Type aliases for common configuration structures
type (
	PKI     = config.PKI
	Voting  = config.Voting
	Logging = config.Logging
)

type Config struct {
	// PKI is the Katzenpost directory authority authority client configuration.
	PKI *PKI

	// Logging is the logging configuration.
	Logging *Logging

	// DataDir is the absolute path to the server's state files.
	DataDir string

	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// ReplicaID is the static uint8 identifier for this replica.
	// This must match the ReplicaID configured in all dirauths for this replica.
	ReplicaID uint8

	// WireKEMScheme is the wire protocol KEM scheme to use.
	WireKEMScheme string

	// PKISignatureScheme specifies the cryptographic signature scheme
	PKISignatureScheme string

	// ReplicaNIKEScheme specifies the cryptographic signature scheme
	ReplicaNIKEScheme string

	// SphinxGeometry is the Sphinx Geometry being used on the mixnet.
	SphinxGeometry *geo.Geometry

	// Addresses are the IP address/port combinations that the server will bind
	// to for incoming connections.
	Addresses []string

	// BindAddresses are the listener addresses that the server will bind to and accept connections on
	// These Addresses are not advertised in the PKI.
	BindAddresses []string

	// ConnectTimeout specifies the maximum time a connection can take to
	// establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// HandshakeTimeout specifies the maximum time a connection can take for a
	// link protocol handshake in milliseconds.
	HandshakeTimeout int

	// ReauthInterval specifies the interval at which a connection will be
	// reauthenticated in milliseconds.
	ReauthInterval int

	// OutgoingQueueSize specifies the maximum number of commands that can be
	// queued for outgoing connections.
	OutgoingQueueSize int

	// IncomingQueueSize is the buffer size for the incoming-connection
	// sender queue. Omit this field (or set it to 0) on a
	// single-replica-per-host deployment so the runtime can pick a
	// sensible value from runtime.NumCPU and the CTIDH self-check; an
	// explicit non-zero value overrides the auto-derivation and is
	// intended for unusual deployments (multi-tenancy on a shared
	// host, intentional small-buffer testing, etc.).
	IncomingQueueSize int

	// KeepAliveInterval specifies the TCP keep-alive interval in milliseconds.
	KeepAliveInterval int

	// ProxyRequestTimeout is the per-proxy-request wall-clock timeout
	// in seconds for waiting on a peer replica's response. Omit this
	// field (or set it to 0) so the runtime can pick a sensible value
	// from the CTIDH self-check's saturated rate; an explicit
	// non-zero value overrides and is intended for unusual cases
	// (research workloads, debugging chaos scenarios with very long
	// per-op times, etc.).
	ProxyRequestTimeout int

	// ProxyWorkerCount caps how many proxy-request handlers can be in
	// flight concurrently. Omit this field (or set it to 0) on a
	// single-replica-per-host deployment so the runtime picks
	// runtime.NumCPU divided by CoTenancyFactor; an explicit non-zero
	// value is intended for unusual deployments where the operator
	// wants to reserve CPU for other work beyond the co-tenanted
	// replicas.
	ProxyWorkerCount int


	// MetricsAddress is the address/port to bind the prometheus metrics endpoint to.
	// If empty, no metrics listener is started.
	MetricsAddress string

	// DisableDecoyTraffic disables sending decoy traffic.
	DisableDecoyTraffic bool

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool

	// MaxStorageMiB, when greater than zero, is a hard quota on the
	// replica database's on-disk size, expressed in mebibytes (1 MiB =
	// 1024*1024 bytes). The quota is enforced against RocksDB's live
	// SST footprint. Writes that would grow the store past this are
	// rejected with ReplicaErrorStorageFull. Zero (the default) leaves
	// the database size unbounded except by the filesystem reserve
	// below.
	MaxStorageMiB int64

	// MinFreeStorageMiB is the filesystem free-space reserve on the
	// DataDir filesystem, in mebibytes (1 MiB = 1024*1024 bytes). New
	// writes are rejected with ReplicaErrorStorageFull once fewer than
	// this many MiB remain available, regardless of MaxStorageMiB, so
	// the replica never fills the host disk. Zero selects
	// DefaultMinFreeStorageMiB (500 MiB); a positive value overrides
	// it.
	MinFreeStorageMiB int64
}

func (c *Config) FixupAndValidate(forceGenOnly bool) error {
	c.SetDefaultTimeouts()

	if err := c.validateRequiredFields(); err != nil {
		return err
	}

	if err := c.validateAndSetupAddresses(); err != nil {
		return err
	}

	if err := c.validateDataDirectory(); err != nil {
		return err
	}

	if err := c.validatePKIConfiguration(); err != nil {
		return err
	}

	if c.MetricsAddress != "" {
		// Accept either an IP literal or a hostname; the prometheus
		// listener resolves whatever we hand it via net.Listen and we
		// rely on the docker bridge to enforce reachability.
		if _, _, err := net.SplitHostPort(c.MetricsAddress); err != nil {
			return fmt.Errorf("config: MetricsAddress '%v' is invalid: %v", c.MetricsAddress, err)
		}
	}

	if c.MaxStorageMiB < 0 {
		return fmt.Errorf("config: MaxStorageMiB must not be negative, got %d", c.MaxStorageMiB)
	}
	if c.MinFreeStorageMiB < 0 {
		return fmt.Errorf("config: MinFreeStorageMiB must not be negative, got %d", c.MinFreeStorageMiB)
	}
	if c.MinFreeStorageMiB == 0 {
		c.MinFreeStorageMiB = DefaultMinFreeStorageMiB
	}

	return c.setupLoggingDefaults()
}

// SetDefaultTimeouts sets default values for timeout configurations
func (c *Config) SetDefaultTimeouts() {
	if c.ReauthInterval <= 0 {
		c.ReauthInterval = config.DefaultReauthInterval
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = config.DefaultHandshakeTimeout
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = config.DefaultConnectTimeout
	}
	if c.OutgoingQueueSize <= 0 {
		c.OutgoingQueueSize = defaultOutgoingQueueSize
	}
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = defaultKeepAliveInterval
	}
	// IncomingQueueSize, ProxyRequestTimeout and ProxyWorkerCount are
	// auto-derived later, in server.New, via ApplyRuntimeDefaults.
	// Leave zero values alone here so they propagate as the
	// "auto-derive" sentinel.
}

// ApplyRuntimeDefaults fills in any zero-valued runtime-tunable
// fields based on the host's CPU count and the saturated CTIDH op
// rate measured at startup. Operators should leave the three
// affected fields unset in their TOML so the runtime can pick
// sensible values; an explicit non-zero value in the TOML wins.
//
// `numCPU` should be `runtime.NumCPU()`. `saturatedOpsPerSec` should
// be the saturated rate from the replica's CTIDH startup
// self-check; pass 0 if no measurement is available, in which case
// the queue and timeout fall back to NumCPU-only defaults.
//
// Note: an earlier revision divided ProxyWorkerCount by an
// operator-declared CoTenancyFactor, on the intuition that fewer
// workers per replica would reduce CPU contention on a co-tenanted
// host. Empirical parallel-load measurements showed the opposite: the
// application-layer semaphore serialised pipeline parallelism more
// aggressively than CPU contention would, and throughput dropped
// 2.5x with a 12x p99 latency increase. The OS scheduler handles CPU
// sharing fine; the application just needs enough work in flight to
// mask network latency. ProxyWorkerCount = runtime.NumCPU regardless
// of how many replicas share the host. The
// `saturatedOpsPerSec` measurement already captures the realised
// contention, so the queue and timeout derivations remain accurate.
func (c *Config) ApplyRuntimeDefaults(numCPU int, saturatedOpsPerSec float64) {
	if c.ProxyWorkerCount <= 0 {
		if numCPU < 1 {
			numCPU = 1
		}
		c.ProxyWorkerCount = numCPU
	}
	if c.IncomingQueueSize <= 0 {
		// Default sizing: enough buffer to absorb 10 seconds of
		// peak-rate bursts. Floor at 64 so very slow hosts still
		// have room for bursty courier handshakes. Without a
		// measurement, use a 32-per-CPU heuristic.
		const targetSeconds = 10.0
		const minBuffer = 64
		size := minBuffer
		if saturatedOpsPerSec > 0 {
			derived := int(saturatedOpsPerSec*targetSeconds) + 1
			if derived > size {
				size = derived
			}
		}
		if c.ProxyWorkerCount*32 > size {
			size = c.ProxyWorkerCount * 32
		}
		c.IncomingQueueSize = size
	}
	if c.ProxyRequestTimeout <= 0 {
		// Default sizing: 30 per-op times, floored at 30 seconds so
		// chaos and warm-start scenarios get a generous-but-not-
		// absurd window. The legacy 300-second timeout was chosen
		// pre-self-check and overshoots the observed p99 by orders
		// of magnitude.
		const minTimeoutSeconds = 30
		const opMultiplier = 30
		t := minTimeoutSeconds
		if saturatedOpsPerSec > 0 {
			derived := int(opMultiplier/saturatedOpsPerSec) + 1
			if derived > t {
				t = derived
			}
		}
		c.ProxyRequestTimeout = t
	}
}

// validateRequiredFields validates that all required configuration fields are set
func (c *Config) validateRequiredFields() error {
	if c.Identifier == "" {
		return errors.New("config: Server: Identifier is not set")
	}
	if c.WireKEMScheme == "" {
		return errors.New("config: Server: WireKEMScheme is not set")
	}
	if c.PKISignatureScheme == "" {
		return errors.New("config: Server: PKISignatureScheme is not set")
	}
	if c.ReplicaNIKEScheme == "" {
		return errors.New("config: Server: ReplicaNIKEScheme is not set")
	}
	if c.SphinxGeometry == nil {
		return errors.New("config: SphinxGeometry must not be nil")
	}
	return nil
}

// validateAndSetupAddresses validates existing addresses or sets up default ones
func (c *Config) validateAndSetupAddresses() error {
	if c.Addresses != nil {
		return c.validateExistingAddresses()
	}
	return c.setupDefaultAddress()
}

// validateExistingAddresses validates the configured addresses
func (c *Config) validateExistingAddresses() error {
	for _, v := range c.Addresses {
		if u, err := url.Parse(v); err != nil {
			return fmt.Errorf("config: Authority: Address '%v' is invalid: %v", v, err)
		} else if u.Port() == "" {
			return fmt.Errorf("config: Authority: Address '%v' is invalid: Must contain Port", v)
		}
	}
	return nil
}

// setupDefaultAddress sets up a default external IPv4 address
func (c *Config) setupDefaultAddress() error {
	// Try to guess a "suitable" external IPv4 address.  If people want
	// to do loopback testing, they can manually specify one.  If people
	// want to use IPng, they can manually specify that as well.
	addr, err := utils.GetExternalIPv4Address()
	if err != nil {
		return err
	}
	c.Addresses = []string{"tcp://" + addr.String() + defaultAddress}
	return nil
}

// validateDataDirectory validates that the data directory is an absolute path
func (c *Config) validateDataDirectory() error {
	if !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", c.DataDir)
	}
	return nil
}

// validatePKIConfiguration validates that PKI configuration is present
func (c *Config) validatePKIConfiguration() error {
	if c.PKI == nil {
		return errors.New("config: No PKI block was present")
	}
	return nil
}

// setupLoggingDefaults sets up default logging configuration and validates it
func (c *Config) setupLoggingDefaults() error {
	// Handle missing sections if possible.
	if c.Logging == nil {
		defaultLogging := config.DefaultLogging()
		c.Logging = &defaultLogging
	}
	return c.Logging.Validate()
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	err := config.LoadConfigFromBytes(b, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(forceGenOnly); err != nil {
		return nil, err
	}

	if forceGenOnly {
		cfg.GenerateOnly = true
	}

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the
// Config.
func LoadFile(f string, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	err := config.LoadConfigFromFile(f, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(forceGenOnly); err != nil {
		return nil, err
	}

	if forceGenOnly {
		cfg.GenerateOnly = true
	}

	return cfg, nil
}
