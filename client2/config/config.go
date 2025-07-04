// SPDX-FileCopyrightText: Copyright (C) 2018-2023  Yawning Angel, David Stainton.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"

	"github.com/katzenpost/katzenpost/client2/proxy"
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
	case "ERROR", "WARNING", "INFO", "DEBUG":
	case "":
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl
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
	// the value too far WILL result in unnecessary Gateway load, and
	// increasing the value too far WILL adversely affect large message
	// transmit performance.
	PollingInterval int

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

// Gateway describes all necessary Gateway connection information
// so that clients can connect to the Gateway and use the mixnet
// and retrieve cached PKI documents.
type Gateway struct {
	// WireKEMScheme specifies which KEM to use with our PQ Noise based wire protocol.
	WireKEMScheme string

	// Name is the human readable (descriptive) node identifier.
	Name string

	// IdentityKey is the node's identity (signing) key.
	IdentityKey sign.PublicKey

	// LinkKey is the node's wire protocol public key.
	LinkKey kem.PublicKey

	// PKISignatureScheme specifies the signature scheme to use with the PKI protocol.
	PKISignatureScheme string

	// Addresses are the URLs specifying the endpoints that can be used to reach the node.
	// Valid schemes are tcp:// and quic:// for TCP and quic (UDP)
	Addresses []string
}

func (p *Gateway) UnmarshalTOML(v interface{}) error {
	data, _ := v.(map[string]interface{})
	p.Name = data["Name"].(string)
	var err error

	if data["PKISignatureScheme"].(string) == "" {
		panic("PKISignatureScheme is an empty string")
	}

	sigScheme := signSchemes.ByName(data["PKISignatureScheme"].(string))
	if sigScheme == nil {
		panic("pki signature scheme is nil")
	}

	p.IdentityKey, err = signpem.FromPublicPEMString(data["IdentityKey"].(string), sigScheme)
	if err != nil {
		return err
	}

	if data["WireKEMScheme"].(string) == "" {
		return errors.New("WireKEMScheme is empty string")
	}

	kemscheme := schemes.ByName(data["WireKEMScheme"].(string))
	if kemscheme == nil {
		return errors.New("WireKEMScheme is nil")
	}
	p.LinkKey, err = kempem.FromPublicPEMString(data["LinkKey"].(string), kemscheme)
	if err != nil {
		return err
	}

	// XXX toml.Decode does not return []string for this field :-(
	addrs, ok := data["Addresses"].([]interface{})
	if !ok {
		return fmt.Errorf("%v", data)
	}
	addresses, err := getAddresses(addrs)
	if err != nil {
		return err
	}
	p.Addresses = addresses
	return nil
}

// getAddresses extacts valid Address lines from toml interface soup
func getAddresses(addrs []interface{}) ([]string, error) {
	addresses := make([]string, 0)
	for _, addr := range addrs {
		addr, ok := addr.(string)
		if !ok {
			return addresses, fmt.Errorf("Address decode failure, not a string: %v", addr)
		}
		u, err := url.Parse(addr)
		if err != nil {
			return addresses, fmt.Errorf("Address URL decode failure: %v", err)
		}
		switch u.Scheme {
		case cpki.TransportTCP, cpki.TransportTCPv4, cpki.TransportTCPv6, cpki.TransportQUIC, cpki.TransportOnion:
			addresses = append(addresses, u.String())
		default:
			return addresses, fmt.Errorf("Address Invalid Scheme: %v", u.String())
		}
	}
	if len(addresses) == 0 {
		return addresses, fmt.Errorf("No valid Addresses in %v", addrs)
	}
	return addresses, nil
}

// VotingAuthority is a voting authority peer public configuration: key material, connection info etc.
type VotingAuthority struct {
	Peers []*vServerConfig.Authority
}

type Gateways struct {
	Gateways []*Gateway
}

type Callbacks struct {
	// OnConnFn is the callback function that will be called when the
	// connection status changes.  The error parameter will be nil on
	// successful connection establishment, otherwise it will be set
	// with the reason why a connection has been torn down (or a connect
	// attempt has failed).
	OnConnFn func(error)

	// OnMessageEmptyFn is the callback function that will be called
	// when the user's server side spool is empty.  This can happen
	// as the result of periodic background fetches.  Calls to the callback
	// that return an error will be treated as a signal to tear down the
	// connection.
	OnEmptyFn func() error

	// OnMessageFn is the callback function that will be called when
	// a message is retrived from the user's server side spool.  Callers
	// MUST be prepared to receive multiple callbacks with the same
	// message body.  Calls to the callback that return an error will
	// be treated as a signal to tear down the connection.
	OnMessageFn func([]byte) error

	// OnACKFn is the callback function that will be called when a
	// message CK is retreived from the user's server side spool.  Callers
	// MUST be prepared to receive multiple callbacks with the same
	// SURB ID and SURB ciphertext.  Calls to the callback that return
	// an error will be treated as a signal to tear down the connection.
	OnACKFn func(*[constants.SURBIDLength]byte, []byte) error

	// OnDocumentFn is the callback function taht will be called when a
	// new directory document is retreived for the current epoch.
	OnDocumentFn func(*cpki.Document)
}

// Config is the top level client configuration.
type Config struct {

	// ListenNetwork is the network type that the daemon should listen on for thin client connections.
	ListenNetwork string

	// ListenAddress is the network address that the daemon should listen on for thin client connections.
	ListenAddress string

	// PKISignatureScheme specifies the signature scheme to use with the PKI protocol.
	PKISignatureScheme string

	// WireKEMScheme specifies which KEM to use with our PQ Noise based wire protocol.
	WireKEMScheme string

	// SphinxGeometry
	SphinxGeometry *geo.Geometry

	// PigeonholeGeometry
	PigeonholeGeometry *pigeonholeGeo.Geometry

	// Logging
	Logging *Logging

	// UpstreamProxy can be used to setup a SOCKS proxy for use with a VPN or Tor.
	UpstreamProxy *UpstreamProxy

	// Debug is used to set various parameters.
	Debug *Debug

	// CachedDocument is a PKI Document that has a MixDescriptor
	// containg the Addresses and LinkKeys of minclient's Gateway
	// so that it can connect directly without contacting an Authority.
	CachedDocument *cpki.Document

	// PinnedGateways is information about a set of Gateways; the required information that lets clients initially
	// connect and download a cached PKI document.
	PinnedGateways *Gateways

	// VotingAuthority contains the voting authority peer public configuration.
	VotingAuthority *VotingAuthority

	// Callbacks should not be set by the config file.
	Callbacks *Callbacks

	// PreferedTransports is a list of the transports will be used to make
	// outgoing network connections, with the most prefered first.
	PreferedTransports []string

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
	if c.WireKEMScheme == "" {
		return errors.New("WireKEMScheme is empty string")
	}
	kemscheme := schemes.ByName(c.WireKEMScheme)
	if kemscheme == nil {
		return errors.New("WireKEMScheme is nil")
	}
	if c.PinnedGateways == nil {
		return errors.New("config: No PinnedGateways block was present")
	}
	if c.SphinxGeometry == nil {
		return errors.New("config: No SphinxGeometry block was present")
	}
	err := c.SphinxGeometry.Validate()
	if err != nil {
		return err
	}
	if c.PigeonholeGeometry == nil {
		return errors.New("config: No PigeonholeGeometry block was present")
	}
	err = c.PigeonholeGeometry.Validate()
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
