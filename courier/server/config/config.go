// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	defaultLogLevel         = "NOTICE"
	DefaultConnectTimeout   = 60 * 1000 // 60 sec.
	DefaultHandshakeTimeout = 30 * 1000 // 30 sec.
	DefaultReauthInterval   = 30 * 1000 // 30 sec.
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

	// WireKEMScheme is the wire protocol KEM scheme to be used.
	WireKEMScheme string

	// DataDir is the absolute path to the server's directory for storing files
	// like the wire protocol keys for example.
	DataDir string

	// ServiceNodeDataDir is the absolute path to our service node's data dir.
	// We need read access to this path so that we can read the private and public
	// wire protocol keys (link layer keys).
	ServiceNodeDataDir string

	// SphinxGeometry is used for our wire protocol connection to the dirauths.
	SphinxGeometry *geo.Geometry

	// ConnectTimeout specifies the maximum time a connection can take to
	// establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// HandshakeTimeout specifies the maximum time a connection can take for a
	// link protocol handshake in milliseconds.
	HandshakeTimeout int

	// ReauthInterval specifies the interval at which a connection will be
	// reauthenticated in milliseconds.
	ReauthInterval int
}

func (c *Config) FixupAndValidate() error {
	if c.PKI == nil {
		return errors.New("config: No PKI block was present")
	}
	if c.Logging == nil {
		c.Logging = &defaultLogging
	}
	if err := c.Logging.validate(); err != nil {
		return err
	}
	if c.WireKEMScheme == "" {
		return errors.New("config: Server: WireKEMScheme is not set")
	}
	if !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", c.DataDir)
	}
	if !filepath.IsAbs(c.ServiceNodeDataDir) {
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", c.DataDir)
	}
	if c.SphinxGeometry == nil {
		return errors.New("config: SphinxGeometry must not be nil")
	}
	if c.ReauthInterval <= 0 {
		c.ReauthInterval = DefaultReauthInterval
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	err := toml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
