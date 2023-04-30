// SPDX-FileCopyrightText: 2023, David Stainton <dstainton415@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"

	"github.com/katzenpost/katzenpost/client2/internal/proxy"
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
	PreferedTransports []cpki.Transport

	// EnableTimeSync enables the use of skewed remote provider time
	// instead of system time when available.
	EnableTimeSync bool
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

type PinnedProviders struct {
	Providers []*Provider
}

// Provider describes all necessary Provider connection information
// so that clients can connect to the Provider and use the mixnet
// and retrieve cached PKI documents.
type Provider struct {
	// Name is the human readable (descriptive) node identifier.
	Name string

	// IdentityKey is the node's identity (signing) key.
	IdentityKey sign.PublicKey

	// LinkKey is the node's wire protocol public key.
	LinkKey wire.PublicKey

	// Addresses is the map of transport to address combinations that can
	// be used to reach the node.
	Addresses map[string][]string
}

func (p *Provider) UnmarshalTOML(v interface{}) error {
	_, p.IdentityKey = cert.Scheme.NewKeypair()
	_, p.LinkKey = wire.DefaultScheme.GenerateKeypair(rand.Reader)

	data, _ := v.(map[string]interface{})
	p.Name = data["Name"].(string)
	err := p.IdentityKey.UnmarshalText([]byte(data["IdentityKey"].(string)))
	if err != nil {
		return err
	}
	err = p.LinkKey.UnmarshalText([]byte(data["LinkKey"].(string)))
	if err != nil {
		return err
	}

	m := data["Addresses"].(map[string]interface{})
	p.Addresses = make(map[string][]string)

	for k, v := range m {
		values := make([]string, 0)
		if v == nil {
			return fmt.Errorf("error: KEY %s has nil value\n", k)
		} else {
			vals := v.([]interface{})
			for i := 0; i < len(vals); i++ {
				values = append(values, vals[i].(string))
			}
		}
		p.Addresses[k] = values
	}

	return nil
}

// Config is the top level client configuration.
type Config struct {
	// PinnedProviders
	PinnedProviders *PinnedProviders

	// SphinxGeometry
	SphinxGeometry *geo.Geometry

	// Logging
	Logging *Logging

	// LogBackend is the logging backend to use for client logging.
	LogBackend *log.Backend

	// PKIClient is the PKI Document data source.
	PKIClient cpki.Client

	// UpstreamProxy can be used to setup a SOCKS proxy for use with a VPN or Tor.
	UpstreamProxy *UpstreamProxy

	// Debug is used to set various parameters.
	Debug *Debug

	// CachedDocument is a PKI Document that has a MixDescriptor
	// containg the Addresses and LinkKeys of minclient's Provider
	// so that it can connect directly without contacting an Authority.
	CachedDocument *cpki.Document

	upstreamProxy *proxy.Config
}

// UpstreamProxyConfig returns the configured upstream proxy, suitable for
// internal use.  Most people should not use this.
func (c *Config) UpstreamProxyConfig() *proxy.Config {
	return c.upstreamProxy
}

// FixupAndValidate applies defaults to config entries and validates the
// configuration sections.
func (c *Config) FixupAndValidate() error {
	if c.PinnedProviders == nil {
		return errors.New("config: No PinnedProviders block was present")
	}
	if len(c.PinnedProviders.Providers) == 0 {
		return errors.New("config: No PinnedProviders block was present")
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
