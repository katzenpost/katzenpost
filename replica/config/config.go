// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"

	"github.com/katzenpost/katzenpost/common/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	defaultAddress                = ":3266"
	defaultReplicationQueueLength = 100        // Default queue length for replication operations
	defaultOutgoingQueueSize      = 64         // Default queue size for outgoing connections
	defaultIncomingQueueSize      = 1000       // Default queue size for incoming connection sender
	defaultKeepAliveInterval      = 180 * 1000 // Default TCP keep-alive interval (3 minutes)
	defaultReplicationWorkerCount = 4          // Default number of replication worker goroutines
	defaultProxyRequestTimeout    = 300        // Default proxy request timeout in seconds (5 minutes)
	defaultProxyWorkerCount       = 8          // Default number of proxy request worker goroutines
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

	// ReplicationQueueLength specifies the maximum number of items that can be
	// queued for replication operations.
	ReplicationQueueLength int

	// OutgoingQueueSize specifies the maximum number of commands that can be
	// queued for outgoing connections.
	OutgoingQueueSize int

	// IncomingQueueSize specifies the buffer size for the incoming connection
	// sender queue. This must be large enough to absorb response bursts
	// between sender ticks without blocking command processing.
	IncomingQueueSize int

	// KeepAliveInterval specifies the TCP keep-alive interval in milliseconds.
	KeepAliveInterval int

	// ReplicationWorkerCount specifies the number of goroutines in the
	// replication worker pool. Higher values allow more concurrent replication
	// to shard members under high write load.
	ReplicationWorkerCount int

	// ProxyRequestTimeout specifies the timeout in seconds for proxy requests
	// to other replicas. This must be long enough for the request to traverse
	// the replica-to-replica connection under decoy traffic load.
	ProxyRequestTimeout int

	// ProxyWorkerCount specifies the number of goroutines that handle proxy
	// requests concurrently. This prevents proxy requests from blocking the
	// incoming connection command loop.
	ProxyWorkerCount int

	// MetricsAddress is the address/port to bind the prometheus metrics endpoint to.
	// If empty, no metrics listener is started.
	MetricsAddress string

	// DisableDecoyTraffic disables sending decoy traffic.
	DisableDecoyTraffic bool

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool
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
		if _, err := netip.ParseAddrPort(c.MetricsAddress); err != nil {
			return fmt.Errorf("config: MetricsAddress '%v' is invalid: %v", c.MetricsAddress, err)
		}
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
	if c.ReplicationQueueLength <= 0 {
		c.ReplicationQueueLength = defaultReplicationQueueLength
	}
	if c.OutgoingQueueSize <= 0 {
		c.OutgoingQueueSize = defaultOutgoingQueueSize
	}
	if c.IncomingQueueSize <= 0 {
		c.IncomingQueueSize = defaultIncomingQueueSize
	}
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = defaultKeepAliveInterval
	}
	if c.ReplicationWorkerCount <= 0 {
		c.ReplicationWorkerCount = defaultReplicationWorkerCount
	}
	if c.ProxyRequestTimeout <= 0 {
		c.ProxyRequestTimeout = defaultProxyRequestTimeout
	}
	if c.ProxyWorkerCount <= 0 {
		c.ProxyWorkerCount = defaultProxyWorkerCount
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
