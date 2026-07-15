// SPDX-FileCopyrightText: Copyright (C) 2018-2023  Yawning Angel, David Stainton.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/sign"

	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"

	"github.com/katzenpost/katzenpost/client/proxy"
	"github.com/katzenpost/katzenpost/client/transport"
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
		lvl = defaultLogLevel
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

// LinkPublicKey wraps kem.PublicKey with PEM-based text marshaling
// so that BurntSushi/toml can serialize it as a string.
type LinkPublicKey struct {
	kem.PublicKey
}

func (k LinkPublicKey) MarshalText() ([]byte, error) {
	return []byte(kempem.ToPublicPEMString(k.PublicKey)), nil
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
	LinkKey LinkPublicKey

	// PKISignatureScheme specifies the signature scheme to use with the PKI protocol.
	PKISignatureScheme string

	// Addresses are the URLs specifying the endpoints that can be used to reach the node.
	// Valid schemes are tcp:// and quic:// for TCP and quic (UDP)
	Addresses []string
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

	// Listen is the subtable-discriminated listen-transport
	// configuration. Exactly one of its inner subtables (Unix, Tcp,
	// and in future Ssh / Pigeonhole) must be populated.
	Listen *transport.ListenConfig

	// PKISignatureScheme specifies the signature scheme to use with the PKI protocol.
	PKISignatureScheme string

	// WireKEMScheme specifies which KEM to use with our PQ Noise based wire protocol.
	WireKEMScheme string

	// SphinxGeometry
	SphinxGeometry *geo.Geometry

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

	// MetricsAddress is the bind address of the kpclientd prometheus
	// listener. The listener is only compiled in when the
	// `kpclientd_metrics` build tag is set; production builds without
	// the tag treat this field as inert. Convention is 127.0.0.1
	// only; binding to a public address is not supported.
	MetricsAddress string

	// AllowHostnameAddresses, when true, permits DNS hostnames in
	// the Listen Tcp address, MetricsAddress, PinnedGateways
	// addresses and VotingAuthority peer addresses. The default is
	// false: production clients must use IP literals so the daemon
	// never performs a DNS lookup at runtime. Genconfig sets this
	// to true for the docker-mixnet thin-client config because the
	// embedded compose DNS resolves daemon hostnames such as
	// kpclientd, gateway1, auth1. Onion addresses are always
	// permitted.
	AllowHostnameAddresses bool

	// SessionGracePeriod sets how long the daemon preserves
	// per-app state (ARQ entries, reply queues, the AppID-to-token
	// mapping) after a thin client's underlying connection drops
	// without a thin_close. A reconnect within the window restores
	// the prior session; an absence beyond it reaps the state.
	// Zero (the unset default) means the compile-time fallback in
	// listener.go applies. Parsed from a Go duration string such as
	// "10m" or "30s".
	SessionGracePeriod time.Duration

	upstreamProxy *proxy.Config
}

// UpstreamProxyConfig returns the configured upstream proxy, suitable for
// internal use.  Most people should not use this.
func (c *Config) UpstreamProxyConfig() *proxy.Config {
	return c.upstreamProxy
}

// VotingAuthority is a voting authority peer public configuration: key material, connection info etc.
type VotingAuthority struct {
	Peers []*vServerConfig.Authority
}
