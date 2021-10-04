// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
// 
// config.go - Katzenpost catshadow configuration.
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

// Package config implements the configuration for catshadow.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// Config is the top level catshadow configuration.
type Config struct {
	ClientLogging      *config.Logging
	Logging            *config.Logging
	UpstreamProxy      *config.UpstreamProxy
	Debug              *config.Debug
	NonvotingAuthority *config.NonvotingAuthority
	VotingAuthority    *config.VotingAuthority
}

func (c *Config) ClientConfig() (*config.Config, error) {
	cfg := &config.Config{
		Logging:            c.ClientLogging,
		UpstreamProxy:      c.UpstreamProxy,
		Debug:              c.Debug,
		NonvotingAuthority: c.NonvotingAuthority,
		VotingAuthority:    c.VotingAuthority,
	}
	err := cfg.FixupAndValidate()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) InitLogBackend() (*log.Backend, error) {
	f := c.Logging.File
	if !c.Logging.Disable && c.Logging.File != "" {
		if !filepath.IsAbs(f) {
			return nil, errors.New("log file path must be absolute path")
		}
	}
	var err error
	logBackend, err := log.New(f, c.Logging.Level, c.Logging.Disable)
	if err != nil {
		return nil, err
	}
	return logBackend, nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	md, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("config: Undecoded keys in config file: %v", undecoded)
	}
	return cfg, nil
}

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
