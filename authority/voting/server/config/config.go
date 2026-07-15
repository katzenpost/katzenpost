// config.go - Katzenpost voting authority server configuration.
// Copyright (C) 2017  Yawning Angel.
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

// Package config implements the Katzenpost voting authority server
// configuration.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	defaultAddress          = ":62472"
	defaultLogLevel         = "NOTICE"
	defaultLayers           = 3
	defaultMinNodesPerLayer = 2

	// Note: These values are picked primarily for debugging and need to
	// be changed to something more suitable for a production deployment
	// at some point. Sampling safety caps are derived inside
	// common.SafetyCap from each rate, so no MaxDelay companion
	// defaults are needed here.
	defaultMu      = 0.00025
	defaultLambdaP = 0.00025
	defaultLambdaL = 0.00025
	defaultLambdaM = 0.00025
	defaultLambdaR = 0.00025

	publicKeyHashSize = 32
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Logging is the authority logging configuration.
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

// Parameters is the network parameters.
//
// Sampling safety caps are derived programmatically from each rate
// inside common.SafetyCap and are not operator-tunable. The earlier
// MuMaxDelay, LambdaPMaxDelay, LambdaLMaxDelay, LambdaMMaxDelay,
// LambdaGMaxDelay, and LambdaRMaxDelay fields are removed from the
// consensus parameter set; supplying them in authority.toml is no
// longer accepted.
type Parameters struct {
	// Mu is the inverse of the mean of the exponential distribution
	// that is used to select the delay for each hop.
	Mu float64

	// LambdaP is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending from their egress
	// FIFO queue or drop decoy message.
	LambdaP float64

	// LambdaL is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending loop decoys.
	LambdaL float64

	// LambdaM is the inverse of the mean of the exponential distribution
	// that is used to select the delay between sending mix node decoys.
	LambdaM float64

	// LambdaR is the inverse of the mean of the exponential distribution
	// that the courier and storage replicas will sample to determine the
	// send timing of decoy traffic between each other.
	LambdaR float64
}

func (pCfg *Parameters) validate() error {
	if pCfg.Mu < 0 {
		return fmt.Errorf("config: Parameters: Mu %v is invalid", pCfg.Mu)
	}
	if pCfg.LambdaP < 0 {
		return fmt.Errorf("config: Parameters: LambdaP %v is invalid", pCfg.LambdaP)
	}
	if pCfg.LambdaL < 0 {
		return fmt.Errorf("config: Parameters: LambdaL %v is invalid", pCfg.LambdaL)
	}
	if pCfg.LambdaM < 0 {
		return fmt.Errorf("config: Parameters: LambdaM %v is invalid", pCfg.LambdaM)
	}
	if pCfg.LambdaR < 0 {
		return fmt.Errorf("config: Parameters: LambdaR %v is invalid", pCfg.LambdaR)
	}
	return nil
}

func (pCfg *Parameters) applyDefaults() {
	if pCfg.Mu == 0 {
		pCfg.Mu = defaultMu
	}
	if pCfg.LambdaP == 0 {
		pCfg.LambdaP = defaultLambdaP
	}
	if pCfg.LambdaL == 0 {
		pCfg.LambdaL = defaultLambdaL
	}
	if pCfg.LambdaM == 0 {
		pCfg.LambdaM = defaultLambdaM
	}
	if pCfg.LambdaR == 0 {
		pCfg.LambdaR = defaultLambdaR
	}
}

// Debug is the authority debug configuration.
type Debug struct {
	// Layers is the number of non-provider layers in the network topology.
	Layers int

	// MinNodesPerLayer is the minimum number of nodes per layer required to
	// form a valid Document.
	MinNodesPerLayer int

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool
}

func (dCfg *Debug) validate() error {
	if dCfg.Layers > defaultLayers {
		// This is a limitation of the Sphinx implementation.
		return fmt.Errorf("config: Debug: Layers %v exceeds maximum", dCfg.Layers)
	}
	return nil
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.Layers <= 0 {
		dCfg.Layers = defaultLayers
	}
	if dCfg.MinNodesPerLayer <= 0 {
		dCfg.MinNodesPerLayer = defaultMinNodesPerLayer
	}
}

// LinkPublicKey wraps kem.PublicKey with PEM-based text marshaling
// so that BurntSushi/toml can serialize it as a string.
type LinkPublicKey struct {
	kem.PublicKey
}

func (k LinkPublicKey) MarshalText() ([]byte, error) {
	return []byte(kempem.ToPublicPEMString(k.PublicKey)), nil
}

// Authority is the authority configuration for a peer.
type Authority struct {
	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// IdentityPublicKeyPem is a string in PEM format containing
	// the public identity key key.
	IdentityPublicKey sign.PublicKey

	// PKISignatureScheme specifies the cryptographic signature scheme
	PKISignatureScheme string

	// LinkPublicKeyPem is string containing the PEM format of the peer's public link layer key.
	LinkPublicKey LinkPublicKey
	// WireKEMScheme is the wire protocol KEM scheme to use.
	WireKEMScheme string
	// Addresses are the listener addresses specified by a URL, e.g. tcp://1.2.3.4:1234 or quic://1.2.3.4:1234
	// Both IPv4 and IPv6 as well as hostnames are valid.
	Addresses []string
	// BindAddresses are the IP addresses to bind to for incoming connections.
	// If left empty, Addresses will be used.
	BindAddresses []string
}

// Node is an authority mix node or provider entry.
type Node struct {
	// Identifier is the human readable node identifier, to be set iff
	// the node is a Provider.
	Identifier string

	// IdentityPublicKeyPem is the node's public signing key also known
	// as the identity key.
	IdentityPublicKeyPem string
}

func (n *Node) validate(isProvider bool) error {
	if n.Identifier == "" {
		return errors.New("config: Node is missing Identifier")
	}
	var err error
	n.Identifier, err = idna.Lookup.ToASCII(n.Identifier)
	if err != nil {
		return fmt.Errorf("config: Failed to normalize Identifier: %v", err)
	}
	if n.IdentityPublicKeyPem == "" {
		return errors.New("config: Node is missing IdentityPublicKeyPem")
	}
	return nil
}

// StorageReplicaNode is a storage replica node entry.
type StorageReplicaNode struct {
	// Identifier is the human readable node identifier.
	Identifier string

	// IdentityPublicKeyPem is the node's public signing key also known
	// as the identity key.
	IdentityPublicKeyPem string

	// ReplicaID is the static uint8 identifier for this replica.
	// All dirauths must agree on this value for each replica.
	ReplicaID uint8
}

func (n *StorageReplicaNode) validate() error {
	if n.Identifier == "" {
		return errors.New("config: StorageReplicaNode is missing Identifier")
	}
	var err error
	n.Identifier, err = idna.Lookup.ToASCII(n.Identifier)
	if err != nil {
		return fmt.Errorf("config: Failed to normalize Identifier: %v", err)
	}
	if n.IdentityPublicKeyPem == "" {
		return errors.New("config: StorageReplicaNode is missing IdentityPublicKeyPem")
	}
	return nil
}

type Server struct {
	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// WireKEMScheme is the wire protocol KEM scheme to use.
	WireKEMScheme string

	// PKISignatureScheme specifies the cryptographic signature scheme
	PKISignatureScheme string

	// Addresses are the IP address/port combinations that the server will bind
	// to for incoming connections.
	Addresses []string

	// BindAddresses are the IP addresses to bind to for incoming connections.
	// If left empty, Addresses will be used.
	BindAddresses []string

	// DataDir is the absolute path to the server's state files.
	DataDir string

	// Network timeout configuration for authority operations
	// These timeouts are used for both incoming and outgoing connections
	// and should be tuned for post-quantum crypto performance

	// DialTimeoutSec is the timeout for TCP connection establishment (default: 30)
	DialTimeoutSec int

	// HandshakeTimeoutSec is the timeout for wire protocol handshake completion (default: 3)
	HandshakeTimeoutSec int

	// ResponseTimeoutSec is the timeout for command send/receive operations (default: 30)
	ResponseTimeoutSec int

	// CloseDelaySec is the delay before closing connections to allow NoOp finalization (default: 10)
	CloseDelaySec int

	// Peer retry configuration for authority-to-authority communication

	// PeerRetryMaxAttempts is the maximum number of retry attempts for peer communication
	PeerRetryMaxAttempts int

	// PeerRetryBaseDelay is the base delay for exponential backoff between retries
	PeerRetryBaseDelay time.Duration

	// PeerRetryMaxDelay is the maximum delay between retries
	PeerRetryMaxDelay time.Duration

	// PeerRetryJitter is the jitter factor (0.0-1.0) applied to retry delays
	PeerRetryJitter float64

	// DisableIPv4 disables IPv4 for peer connections
	DisableIPv4 bool

	// DisableIPv6 disables IPv6 for peer connections
	DisableIPv6 bool

	// MetricsAddress is the host:port that the dirauth's prometheus
	// HTTP endpoint binds to. Empty disables the endpoint. The
	// listener is wired in server.go after the wire listeners are
	// started; the endpoint is independent of any wire-protocol
	// listener and exposes only metrics, never any authority
	// state.
	MetricsAddress string

	// AllowHostnameAddresses, when true, permits DNS hostnames in
	// Addresses, BindAddresses, MetricsAddress and the per-authority
	// Authority.Addresses lists. The default is false: a production
	// dirauth deployment must use IP literals so the daemon never
	// performs a DNS lookup at runtime. Genconfig sets this to true
	// when generating docker-mixnet configs where dirauths reach
	// each other via container hostnames resolved by the
	// compose-runtime's embedded DNS. Onion addresses are always
	// permitted.
	AllowHostnameAddresses bool
}

// applyRetryDefaults sets default values for retry configuration
func (sCfg *Server) applyRetryDefaults() {
	if sCfg.PeerRetryMaxAttempts == 0 {
		sCfg.PeerRetryMaxAttempts = retry.DefaultMaxAttempts
	}
	if sCfg.PeerRetryBaseDelay == 0 {
		sCfg.PeerRetryBaseDelay = retry.DefaultBaseDelay
	}
	if sCfg.PeerRetryMaxDelay == 0 {
		sCfg.PeerRetryMaxDelay = retry.DefaultMaxDelay
	}
	if sCfg.PeerRetryJitter == 0 {
		sCfg.PeerRetryJitter = retry.DefaultJitter
	}
}

// Config is the top level authority configuration.
type Config struct {
	Server      *Server
	Authorities []*Authority
	Logging     *Logging
	Parameters  *Parameters
	Debug       *Debug

	Mixes           []*Node
	GatewayNodes    []*Node
	ServiceNodes    []*Node
	StorageReplicas []*StorageReplicaNode
	Topology        *Topology

	SphinxGeometry *geo.Geometry
}

// Layer holds a slice of Nodes
type Layer struct {
	Nodes []Node
}

// Topology contains a slice of Layers, each containing a slice of Nodes
type Topology struct {
	Layers []Layer
}

// ValidateAuthorities takes as an argument the dirauth server's own public key
// and tries to find a match in the dirauth peers. Returns an error if no
// match is found. Dirauths must be their own peer.
func (cfg *Config) ValidateAuthorities(linkPubKey kem.PublicKey) error {
	match := false
	for i := 0; i < len(cfg.Authorities); i++ {
		if linkPubKey.Equal(cfg.Authorities[i].LinkPublicKey) {
			match = true
		}
	}
	if !match {
		return errors.New("Authority must be it's own peer")
	}
	return nil
}
