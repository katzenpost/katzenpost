// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	defaultAddress          = ":3266"
	defaultLogLevel         = "NOTICE"
	defaultConnectTimeout   = 60 * 1000  // 60 sec.
	defaultHandshakeTimeout = 30 * 1000  // 30 sec.
	defaultReauthInterval   = 300 * 1000 // 300 sec.
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// PKI is the Katzenpost directory authority configuration.
type PKI struct {
	Voting *Voting
}

func (pCfg *PKI) validate(datadir string) error {
	if pCfg.Voting == nil {
		return errors.New("Voting is nil")
	}
	return nil
}

// Voting is a set of Authorities that vote on a threshold consensus PKI
type Voting struct {
	Authorities []*config.Authority
}

func (vCfg *Voting) validate(datadir string) error {
	if vCfg.Authorities == nil {
		return errors.New("Authorities is nil")
	}
	for _, auth := range vCfg.Authorities {
		err := auth.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Logging is the Katzenpost server logging configuration.
type Logging struct {
	// Disable disables logging entirely.
	Disable bool

	// File specifies the log file, if omitted stdout will be used.
	File string

	// Level specifies the log level.
	Level string
}

func (lCfg *Logging) validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

type Config struct {
	// PKI is the Katzenpost directory authority client configuration.
	PKI *PKI

	// Logging is the logging configuration.
	Logging *Logging

	// DataDir is the absolute path to the server's state files.
	DataDir string

	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

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

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool
}

func (c *Config) FixupAndValidate(forceGenOnly bool) error {
	c.setDefaultTimeouts()

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

	return c.setupLoggingDefaults()
}

// setDefaultTimeouts sets default values for timeout configurations
func (c *Config) setDefaultTimeouts() {
	if c.ReauthInterval <= 0 {
		c.ReauthInterval = defaultReauthInterval
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = defaultConnectTimeout
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
		c.Logging = &defaultLogging
	}
	return c.Logging.validate()
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	err := toml.Unmarshal(b, cfg)
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
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b, forceGenOnly)
}
