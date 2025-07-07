// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/katzenpost/katzenpost/common/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	DefaultMaxQueueSize = 64 // Default outgoing connection queue size.
)

// Type aliases for common configuration structures
type (
	PKI     = config.PKI
	Voting  = config.Voting
	Logging = config.Logging
)

type Config struct {
	// PKI is the Katzenpost directory authority client configuration.
	PKI *PKI

	// Logging is the logging configuration.
	Logging *Logging

	// WireKEMScheme is the wire protocol KEM scheme to be used for our link layer protocol.
	WireKEMScheme string

	// PKIScheme is the signature scheme used by the PKI.
	PKIScheme string

	// EnvelopeNIKEScheme is the NIKE replica scheme for message envelopes.
	EnvelopeScheme string

	// DataDir is the absolute path to the server's directory for storing files
	// like the wire protocol link keys for example.
	DataDir string

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

	// MaxQueueSize specifies the maximum number of messages that can be queued
	// for an outgoing connection before blocking.
	MaxQueueSize int
}

func (c *Config) FixupAndValidate() error {
	if c.PKI == nil {
		return errors.New("config: No PKI block was present")
	}
	if c.Logging == nil {
		defaultLogging := config.DefaultLogging()
		c.Logging = &defaultLogging
	}
	if err := c.Logging.Validate(); err != nil {
		return err
	}
	if c.WireKEMScheme == "" {
		return errors.New("config: Server: WireKEMScheme is not set")
	}
	if !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", c.DataDir)
	}
	if c.SphinxGeometry == nil {
		return errors.New("config: SphinxGeometry must not be nil")
	}
	if c.ReauthInterval <= 0 {
		c.ReauthInterval = config.DefaultReauthInterval
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = config.DefaultHandshakeTimeout
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = config.DefaultConnectTimeout
	}
	if c.MaxQueueSize <= 0 {
		c.MaxQueueSize = DefaultMaxQueueSize
	}
	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	err := config.LoadConfigFromBytes(b, cfg)
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
	cfg := new(Config)
	err := config.LoadConfigFromFile(f, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
