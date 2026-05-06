// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package config provides common configuration structures and utilities
// shared between courier and replica services.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

const (
	// DefaultLogLevel is the default logging level
	DefaultLogLevel = "NOTICE"

	// Common timeout defaults (in milliseconds)
	DefaultConnectTimeout   = 60 * 1000  // 60 sec.
	DefaultHandshakeTimeout = 60 * 1000  // 60 sec.
	DefaultReauthInterval   = 300 * 1000 // 300 sec.
)

// DefaultLogging returns the default logging configuration
func DefaultLogging() Logging {
	return Logging{
		Disable: false,
		File:    "",
		Level:   DefaultLogLevel,
	}
}

// PKI is the Katzenpost directory authority configuration.
type PKI struct {
	Voting *Voting
}

// Validate validates the PKI configuration
func (pCfg *PKI) Validate(datadir string) error {
	if pCfg.Voting == nil {
		return errors.New("Voting is nil")
	}
	return nil
}

// Voting is a set of Authorities that vote on a threshold consensus PKI
type Voting struct {
	Authorities []*config.Authority
}

// Validate validates the Voting configuration
func (vCfg *Voting) Validate(datadir string) error {
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

// Validate validates the logging configuration
func (lCfg *Logging) Validate() error {
	lvl := strings.ToUpper(lCfg.Level)
	switch lvl {
	case "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG":
	case "":
		lCfg.Level = DefaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// LoadConfigFromBytes parses and validates the provided buffer as a TOML config
func LoadConfigFromBytes(b []byte, cfg interface{}) error {
	err := toml.Unmarshal(b, cfg)
	if err != nil {
		return err
	}
	return nil
}

// LoadConfigFromFile loads and parses the provided file as a TOML config
func LoadConfigFromFile(filename string, cfg interface{}) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return LoadConfigFromBytes(b, cfg)
}
