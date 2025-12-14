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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/idna"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	defaultAddress          = ":62472"
	defaultLogLevel         = "NOTICE"
	defaultLayers           = 3
	defaultMinNodesPerLayer = 2
	absoluteMaxDelay        = 6 * 60 * 60 * 1000 // 6 hours.

	// rate limiting of client connections
	defaultSendRatePerMinute = 100

	// Note: These values are picked primarily for debugging and need to
	// be changed to something more suitable for a production deployment
	// at some point.
	defaultMu                   = 0.00025
	defaultMuMaxPercentile      = 0.99999
	defaultLambdaP              = 0.00025
	defaultLambdaPMaxPercentile = 0.99999
	defaultLambdaL              = 0.00025
	defaultLambdaLMaxPercentile = 0.99999
	defaultLambdaD              = 0.00025
	defaultLambdaDMaxPercentile = 0.99999
	defaultLambdaM              = 0.00025
	defaultLambdaMMaxPercentile = 0.99999

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
type Parameters struct {
	// SendRatePerMinute is the rate per minute.
	SendRatePerMinute uint64

	// Mu is the inverse of the mean of the exponential distribution
	// that is used to select the delay for each hop.
	Mu float64

	// MuMaxDelay sets the maximum delay for Mu.
	MuMaxDelay uint64

	// LambdaP is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending from their egress
	// FIFO queue or drop decoy message.
	LambdaP float64

	// LambdaPMaxDelay sets the maximum delay for LambdaP.
	LambdaPMaxDelay uint64

	// LambdaL is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending loop decoys.
	LambdaL float64

	// LambdaLMaxDelay sets the maximum delay for LambdaP.
	LambdaLMaxDelay uint64

	// LambdaD is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending deop decoys.
	LambdaD float64

	// LambdaDMaxDelay sets the maximum delay for LambdaP.
	LambdaDMaxDelay uint64

	// LambdaM is the inverse of the mean of the exponential distribution
	// that is used to select the delay between sending mix node decoys.
	LambdaM float64

	// LambdaG is the inverse of the mean of the exponential distribution
	// that is used to select the delay between sending gateway node decoys.
	//
	// WARNING: This is not used via the TOML config file; this field is only
	// used internally by the dirauth server state machine.
	LambdaG float64

	// LambdaMMaxDelay sets the maximum delay for LambdaP.
	LambdaMMaxDelay uint64

	// LambdaGMaxDelay sets the maximum delay for LambdaG.
	LambdaGMaxDelay uint64
}

func (pCfg *Parameters) validate() error {
	if pCfg.Mu < 0 {
		return fmt.Errorf("config: Parameters: Mu %v is invalid", pCfg.Mu)
	}
	if pCfg.MuMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: MuMaxDelay %v is out of range", pCfg.MuMaxDelay)
	}
	if pCfg.LambdaP < 0 {
		return fmt.Errorf("config: Parameters: LambdaP %v is invalid", pCfg.LambdaP)
	}
	if pCfg.LambdaPMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: LambdaPMaxDelay %v is out of range", pCfg.LambdaPMaxDelay)
	}
	if pCfg.LambdaL < 0 {
		return fmt.Errorf("config: Parameters: LambdaL %v is invalid", pCfg.LambdaP)
	}
	if pCfg.LambdaLMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: LambdaLMaxDelay %v is out of range", pCfg.LambdaPMaxDelay)
	}
	if pCfg.LambdaD < 0 {
		return fmt.Errorf("config: Parameters: LambdaD %v is invalid", pCfg.LambdaP)
	}
	if pCfg.LambdaDMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: LambdaDMaxDelay %v is out of range", pCfg.LambdaPMaxDelay)
	}
	if pCfg.LambdaM < 0 {
		return fmt.Errorf("config: Parameters: LambdaM %v is invalid", pCfg.LambdaP)
	}
	if pCfg.LambdaMMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: LambdaMMaxDelay %v is out of range", pCfg.LambdaPMaxDelay)
	}
	if pCfg.LambdaGMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: LambdaGMaxDelay %v is out of range", pCfg.LambdaPMaxDelay)
	}
	if pCfg.LambdaGMaxDelay == 0 {
		return errors.New("LambdaGMaxDelay must be set")
	}

	return nil
}

func (pCfg *Parameters) applyDefaults() {
	if pCfg.SendRatePerMinute == 0 {
		pCfg.SendRatePerMinute = defaultSendRatePerMinute
	}
	if pCfg.Mu == 0 {
		pCfg.Mu = defaultMu
	}
	if pCfg.MuMaxDelay == 0 {
		pCfg.MuMaxDelay = uint64(rand.ExpQuantile(pCfg.Mu, defaultMuMaxPercentile))
		if pCfg.MuMaxDelay > absoluteMaxDelay {
			pCfg.MuMaxDelay = absoluteMaxDelay
		}
	}
	if pCfg.LambdaP == 0 {
		pCfg.LambdaP = defaultLambdaP
	}
	if pCfg.LambdaPMaxDelay == 0 {
		pCfg.LambdaPMaxDelay = uint64(rand.ExpQuantile(pCfg.LambdaP, defaultLambdaPMaxPercentile))
	}
	if pCfg.LambdaL == 0 {
		pCfg.LambdaL = defaultLambdaL
	}
	if pCfg.LambdaLMaxDelay == 0 {
		pCfg.LambdaLMaxDelay = uint64(rand.ExpQuantile(pCfg.LambdaL, defaultLambdaLMaxPercentile))
	}
	if pCfg.LambdaD == 0 {
		pCfg.LambdaD = defaultLambdaD
	}
	if pCfg.LambdaDMaxDelay == 0 {
		pCfg.LambdaDMaxDelay = uint64(rand.ExpQuantile(pCfg.LambdaD, defaultLambdaDMaxPercentile))
	}
	if pCfg.LambdaM == 0 {
		pCfg.LambdaM = defaultLambdaM
	}
	if pCfg.LambdaMMaxDelay == 0 {
		pCfg.LambdaMMaxDelay = uint64(rand.ExpQuantile(pCfg.LambdaM, defaultLambdaMMaxPercentile))
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
	LinkPublicKey kem.PublicKey
	// WireKEMScheme is the wire protocol KEM scheme to use.
	WireKEMScheme string
	// Addresses are the listener addresses specified by a URL, e.g. tcp://1.2.3.4:1234 or quic://1.2.3.4:1234
	// Both IPv4 and IPv6 as well as hostnames are valid.
	Addresses []string
}

// UnmarshalTOML deserializes into non-nil instances of sign.PublicKey and kem.PublicKey
func (a *Authority) UnmarshalTOML(v interface{}) error {

	data, ok := v.(map[string]interface{})
	if !ok {
		return errors.New("type assertion failed")
	}

	pkiSignatureSchemeStr, ok := data["PKISignatureScheme"].(string)
	if !ok {
		return errors.New("PKISignatureScheme failed type assertion")
	}
	pkiSignatureScheme := signSchemes.ByName(pkiSignatureSchemeStr)
	if pkiSignatureScheme == nil {
		return fmt.Errorf("pki signature scheme `%s` not found", pkiSignatureScheme)
	}
	a.PKISignatureScheme = pkiSignatureSchemeStr

	// identifier
	var err error
	a.IdentityPublicKey, _, err = pkiSignatureScheme.GenerateKey()
	if err != nil {
		return err
	}
	a.Identifier, ok = data["Identifier"].(string)
	if !ok {
		return errors.New("Authority.Identifier type assertion failed")
	}

	// identity key
	idPublicKeyString, _ := data["IdentityPublicKey"].(string)

	a.IdentityPublicKey, err = signpem.FromPublicPEMString(idPublicKeyString, pkiSignatureScheme)
	if err != nil {
		return err
	}

	// link key
	linkPublicKeyString, ok := data["LinkPublicKey"].(string)
	if !ok {
		return errors.New("type assertion failed")
	}

	kemSchemeName, ok := data["WireKEMScheme"].(string)
	if !ok {
		return errors.New("WireKEMScheme failed type assertion")
	}

	a.WireKEMScheme = kemSchemeName
	s := schemes.ByName(kemSchemeName)
	if s == nil {
		return fmt.Errorf("scheme `%s` not found", a.WireKEMScheme)
	}
	a.LinkPublicKey, err = kempem.FromPublicPEMString(linkPublicKeyString, s)
	if err != nil {
		return err
	}

	// address
	addresses := make([]string, 0)
	pos, ok := data["Addresses"]
	if !ok {
		return errors.New("map entry not found")
	}
	for _, addr := range pos.([]interface{}) {
		addresses = append(addresses, addr.(string))
	}
	a.Addresses = addresses
	return nil
}

// Validate parses and checks the Authority configuration.
func (a *Authority) Validate() error {
	if a.WireKEMScheme == "" {
		return errors.New("WireKEMScheme is not set")
	} else {
		s := schemes.ByName(a.WireKEMScheme)
		if s == nil {
			return errors.New("KEM Scheme not found")
		}
	}
	for _, v := range a.Addresses {
		if u, err := url.Parse(v); err != nil {
			return fmt.Errorf("config: Authority: Address '%v' is invalid: %v", v, err)
		} else if u.Port() == "" {
			return fmt.Errorf("config: Authority: Address '%v' is invalid: Must contain Port", v)
		}
	}
	if a.IdentityPublicKey == nil {
		return fmt.Errorf("config: %v: Authority is missing Identity Key", a)
	}

	if a.LinkPublicKey == nil {
		return fmt.Errorf("config: %v: Authority is missing Link Key PEM filename", a)
	}

	return nil
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

	// HandshakeTimeoutSec is the timeout for wire protocol handshake completion (default: 180)
	// Increased for post-quantum crypto operations (KYBER768-X25519 + Ed25519 Sphincs+)
	HandshakeTimeoutSec int

	// ResponseTimeoutSec is the timeout for command send/receive operations (default: 90)
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

// Validate parses and checks the Server configuration.
func (sCfg *Server) validate() error {
	// Set timeout defaults if not specified
	if sCfg.DialTimeoutSec == 0 {
		sCfg.DialTimeoutSec = 30
	}
	if sCfg.HandshakeTimeoutSec == 0 {
		sCfg.HandshakeTimeoutSec = 180
	}
	if sCfg.ResponseTimeoutSec == 0 {
		sCfg.ResponseTimeoutSec = 90
	}
	if sCfg.CloseDelaySec == 0 {
		sCfg.CloseDelaySec = 10
	}

	if sCfg.WireKEMScheme == "" {
		return errors.New("WireKEMScheme was not set")
	} else {
		s := schemes.ByName(sCfg.WireKEMScheme)
		if s == nil {
			return errors.New("KEM Scheme not found")
		}
	}

	if sCfg.PKISignatureScheme == "" {
		return errors.New("PKISignatureScheme was not set")
	} else {
		s := signSchemes.ByName(sCfg.PKISignatureScheme)
		if s == nil {
			return errors.New("PKI Signature Scheme not found")
		}
	}

	if sCfg.Addresses != nil {
		for _, v := range sCfg.Addresses {
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
		sCfg.Addresses = []string{addr.String() + defaultAddress}
	}
	if !filepath.IsAbs(sCfg.DataDir) {
		return fmt.Errorf("config: Authority: DataDir '%v' is not an absolute path", sCfg.DataDir)
	}
	return nil
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
	StorageReplicas []*Node
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
	linkblob1, err := linkPubKey.MarshalText()
	if err != nil {
		return err
	}
	match := false
	for i := 0; i < len(cfg.Authorities); i++ {
		linkblob, err := cfg.Authorities[i].LinkPublicKey.MarshalText()
		if err != nil {
			return err
		}
		if bytes.Equal(linkblob1, linkblob) {
			match = true
		}
	}
	if !match {
		return errors.New("Authority must be it's own peer")
	}
	return nil
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (cfg *Config) FixupAndValidate(forceGenOnly bool) error {

	if cfg.SphinxGeometry == nil {
		return errors.New("config: No SphinxGeometry block was present")
	}

	err := cfg.SphinxGeometry.Validate()
	if err != nil {
		return err
	}

	// Handle missing sections if possible.
	if cfg.Server == nil {
		return errors.New("config: No Authority block was present")
	}
	// Handle missing sections if possible.
	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}
	if cfg.Parameters == nil {
		cfg.Parameters = &Parameters{}
	}
	if cfg.Debug == nil {
		cfg.Debug = &Debug{}
	}

	// Validate and fixup the various sections.
	if err := cfg.Server.validate(); err != nil {
		return err
	}
	if err := cfg.Logging.validate(); err != nil {
		return err
	}
	if err := cfg.Parameters.validate(); err != nil {
		return err
	}
	if err := cfg.Debug.validate(); err != nil {
		return err
	}
	cfg.Parameters.applyDefaults()
	cfg.Debug.applyDefaults()
	cfg.Server.applyRetryDefaults()

	pkiSignatureScheme := signSchemes.ByName(cfg.Server.PKISignatureScheme)

	allNodes := make([]*Node, 0, len(cfg.Mixes)+len(cfg.GatewayNodes)+len(cfg.ServiceNodes))
	for _, v := range cfg.Mixes {
		allNodes = append(allNodes, v)
	}
	for _, v := range cfg.GatewayNodes {
		allNodes = append(allNodes, v)
	}
	for _, v := range cfg.ServiceNodes {
		allNodes = append(allNodes, v)
	}

	var identityKey sign.PublicKey

	if forceGenOnly {
		return nil
	}

	idMap := make(map[string]*Node)
	pkMap := make(map[[publicKeyHashSize]byte]*Node)
	for _, v := range allNodes {
		if _, ok := idMap[v.Identifier]; ok {
			return fmt.Errorf("config: Node: Identifier '%v' is present more than once", v.Identifier)
		}
		if err := v.validate(true); err != nil {
			return err
		}
		idMap[v.Identifier] = v

		identityKey, err = signpem.FromPublicPEMFile(filepath.Join(cfg.Server.DataDir, v.IdentityPublicKeyPem), pkiSignatureScheme)
		if err != nil {
			return err
		}

		tmp := hash.Sum256From(identityKey)
		if _, ok := pkMap[tmp]; ok {
			return fmt.Errorf("config: Nodes: IdentityPublicKeyPem '%v' is present more than once", v.IdentityPublicKeyPem)
		}
		pkMap[tmp] = v
	}

	idMap = make(map[string]*Node)
	pkMap = make(map[[publicKeyHashSize]byte]*Node)
	for _, v := range cfg.StorageReplicas {
		if _, ok := idMap[v.Identifier]; ok {
			return fmt.Errorf("config: Storage Replica Node: Identifier '%v' is present more than once", v.Identifier)
		}
		if err := v.validate(true); err != nil {
			return err
		}
		idMap[v.Identifier] = v

		identityKey, err = signpem.FromPublicPEMFile(filepath.Join(cfg.Server.DataDir, v.IdentityPublicKeyPem), pkiSignatureScheme)
		if err != nil {
			return err
		}

		tmp := hash.Sum256From(identityKey)
		if _, ok := pkMap[tmp]; ok {
			return fmt.Errorf("config: Storage Replica Node: IdentityPublicKeyPem '%v' is present more than once", v.IdentityPublicKeyPem)
		}
		pkMap[tmp] = v
	}

	// if our own identity is not in cfg.Authorities return error
	selfInAuthorities := false

	ourPubKeyFile := filepath.Join(cfg.Server.DataDir, "identity.public.pem")
	f, err := os.Open(ourPubKeyFile)
	if err != nil {
		return err
	}
	pemData, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	ourPubKey, err := signpem.FromPublicPEMBytes(pemData, pkiSignatureScheme)
	if err != nil {
		return err
	}
	ourPubKeyHash := hash.Sum256From(ourPubKey)
	for _, auth := range cfg.Authorities {
		err := auth.Validate()
		if err != nil {
			return err
		}

		if hash.Sum256From(auth.IdentityPublicKey) == ourPubKeyHash {
			selfInAuthorities = true
		}
	}
	if !selfInAuthorities {
		return errors.New("Authorities section must contain self")
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
		cfg.Debug.GenerateOnly = true
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
