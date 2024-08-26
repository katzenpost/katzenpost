// config.go - Katzenpost client configuration.
// Copyright (C) 2018  Yawning Angel, David Stainton.
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

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"

	vClient "github.com/katzenpost/katzenpost/authority/voting/client"
	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client/internal/proxy"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	defaultLogLevel                    = "NOTICE"
	defaultPollingInterval             = 10
	defaultInitialMaxPKIRetrievalDelay = 30
	defaultSessionDialTimeout          = 30
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Logging is the logging configuration.
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

// Debug is the debug configuration.
type Debug struct {
	DisableDecoyTraffic bool

	// SessionDialTimeout is the number of seconds that a session dial
	// is allowed to take until it is canceled.
	SessionDialTimeout int

	// InitialMaxPKIRetrievalDelay is the initial maximum number of seconds
	// we are willing to wait for the retreival of the PKI document.
	InitialMaxPKIRetrievalDelay int

	// PollingInterval is the interval in seconds that will be used to
	// poll the receive queue.  By default this is 10 seconds.  Reducing
	// the value too far WILL result in unnecessary Provider load, and
	// increasing the value too far WILL adversely affect large message
	// transmit performance.
	PollingInterval int

	// PreferedTransports is a list of the transports will be used to make
	// outgoing network connections, with the most prefered first.
	PreferedTransports []string
}

func (d *Debug) fixup() {
	if d.PollingInterval == 0 {
		d.PollingInterval = defaultPollingInterval
	}
	if d.InitialMaxPKIRetrievalDelay == 0 {
		d.InitialMaxPKIRetrievalDelay = defaultInitialMaxPKIRetrievalDelay
	}
	if d.SessionDialTimeout == 0 {
		d.SessionDialTimeout = defaultSessionDialTimeout
	}
}

// VotingAuthority is a voting authority configuration.
type VotingAuthority struct {
	Peers []*vServerConfig.Authority
}

// New constructs a pki.Client with the specified voting authority config.
func (vACfg *VotingAuthority) New(l *log.Backend, pCfg *proxy.Config, linkKey kem.PrivateKey, scheme kem.Scheme, mygeo *geo.Geometry) (pki.Client, error) {
	if scheme == nil {
		return nil, errors.New("KEM scheme cannot be nil")
	}

	blob, err := linkKey.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}
	linkHash := blake2b.Sum256(blob)
	cfg := &vClient.Config{
		KEMScheme:     scheme,
		LinkKey:       linkKey,
		LogBackend:    l,
		Authorities:   vACfg.Peers,
		DialContextFn: pCfg.ToDialContext(fmt.Sprintf("voting: %x", linkHash)),
		Geo:           mygeo,
	}
	return vClient.New(cfg)
}

func (vACfg *VotingAuthority) validate() error {
	if vACfg.Peers == nil || len(vACfg.Peers) == 0 {
		return errors.New("error VotingAuthority failure, must specify at least one peer")
	}
	for _, peer := range vACfg.Peers {
		if peer.IdentityPublicKey == nil || peer.LinkPublicKey == nil || len(peer.Addresses) == 0 {
			return errors.New("invalid voting authority peer")
		}
	}
	return nil
}

// NewPKIClient returns a voting or nonvoting implementation of pki.Client or error
func (c *Config) NewPKIClient(l *log.Backend, pCfg *proxy.Config, linkKey kem.PrivateKey, mygeo *geo.Geometry) (pki.Client, error) {
	switch {
	case c.VotingAuthority != nil:
		return c.VotingAuthority.New(l, pCfg, linkKey, schemes.ByName(c.WireKEMScheme), mygeo)
	}
	return nil, errors.New("no Authority found")
}

// UpstreamProxy is the outgoing connection proxy configuration.
type UpstreamProxy struct {
	// Type is the proxy type (Eg: "none"," socks5").
	Type string

	// Network is the proxy address' network (`unix`, `tcp`).
	Network string

	// Address is the proxy's address.
	Address string

	// User is the optional proxy username.
	User string

	// Password is the optional proxy password.
	Password string
}

func (uCfg *UpstreamProxy) toProxyConfig() (*proxy.Config, error) {
	// This is kind of dumb, but this is the cleanest way I can think of
	// doing this.
	cfg := &proxy.Config{
		Type:     uCfg.Type,
		Network:  uCfg.Network,
		Address:  uCfg.Address,
		User:     uCfg.User,
		Password: uCfg.Password,
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Config is the top level client configuration.
type Config struct {
	RatchetNIKEScheme  string
	WireKEMScheme      string
	PKISignatureScheme string
	SphinxGeometry     *geo.Geometry
	Logging            *Logging
	UpstreamProxy      *UpstreamProxy
	Debug              *Debug
	VotingAuthority    *VotingAuthority
	upstreamProxy      *proxy.Config
}

// UpstreamProxyConfig returns the configured upstream proxy, suitable for
// internal use.  Most people should not use this.
func (c *Config) UpstreamProxyConfig() *proxy.Config {
	return c.upstreamProxy
}

// FixupAndValidate applies defaults to config entries and validates the
// configuration sections.
func (c *Config) FixupAndValidate() error {
	if c.WireKEMScheme == "" {
		return errors.New("config: WireKEMScheme was not set")
	}
	if c.PKISignatureScheme == "" {
		return errors.New("config: PKISignatureScheme was not set")
	}
	if c.SphinxGeometry == nil {
		return errors.New("config: No SphinxGeometry block was present")
	}
	err := c.SphinxGeometry.Validate()
	if err != nil {
		return err
	}
	// Handle missing sections if possible.
	if c.Logging == nil {
		c.Logging = &defaultLogging
	}
	if c.Debug == nil {
		c.Debug = &Debug{
			PollingInterval:             defaultPollingInterval,
			InitialMaxPKIRetrievalDelay: defaultInitialMaxPKIRetrievalDelay,
		}
	} else {
		c.Debug.fixup()
	}

	// Validate/fixup the various sections.
	if err := c.Logging.validate(); err != nil {
		return err
	}
	if uCfg, err := c.UpstreamProxy.toProxyConfig(); err == nil {
		c.upstreamProxy = uCfg
	} else {
		return err
	}
	switch {
	case c.VotingAuthority != nil:
		if err := c.VotingAuthority.validate(); err != nil {
			return fmt.Errorf("config: VotingAuthority is invalid: %s", err)
		}
	case c.VotingAuthority == nil:
		return fmt.Errorf("config: VotingAuthority is invalid: %s", err)
	default:
		return fmt.Errorf("config: Authority configuration is invalid")
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

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
