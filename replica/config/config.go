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
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	defaultAddress  = ":3266"
	defaultLogLevel = "NOTICE"
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

	ThinConfig *thin.ThinConfig

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool
}

func (c *Config) FixupAndValidate(forceGenOnly bool) error {
	if c.ThinConfig == nil {
		return errors.New("config: ThinConfig is not set")
	}
	err := c.ThinConfig.FixupAndValidate()
	if err != nil {
		return err
	}

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

	if c.Addresses != nil {
		for _, v := range c.Addresses {
			if u, err := url.Parse(v); err != nil {
				return fmt.Errorf("config: Authority: Address '%v' is invalid: %v", v, err)
			} else if u.Port() == "" {
				return fmt.Errorf("config: Authority: Address '%v' is invalid: Must contain Port", v)
			}
		}
	} else {
		// Try to guess a "suitable" external IPv4 address.  If people want
		// to do loopback testing, they can manually specify one.  If people
		// want to use IPng, they can manually specify that as well.
		addr, err := utils.GetExternalIPv4Address()
		if err != nil {
			return err
		}

		c.Addresses = []string{"tcp://" + addr.String() + defaultAddress}
	}

	internalTransports := make(map[string]bool)
	for _, v := range pki.InternalTransports {
		internalTransports[strings.ToLower(string(v))] = true
	}

	if !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", c.DataDir)
	}

	if c.PKI == nil {
		return errors.New("config: No PKI block was present")
	}

	// Handle missing sections if possible.
	if c.Logging == nil {
		c.Logging = &defaultLogging
	}

	if err := c.Logging.validate(); err != nil {
		return err
	}

	return nil
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
