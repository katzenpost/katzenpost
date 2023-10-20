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
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/idna"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
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
	// that is used to select the delay between clients sending from their egress
	// FIFO queue or drop decoy message.
	LambdaL float64

	// LambdaLMaxDelay sets the maximum delay for LambdaP.
	LambdaLMaxDelay uint64

	// LambdaD is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending from their egress
	// FIFO queue or drop decoy message.
	LambdaD float64

	// LambdaDMaxDelay sets the maximum delay for LambdaP.
	LambdaDMaxDelay uint64

	// LambdaM is the inverse of the mean of the exponential distribution
	// that is used to select the delay between clients sending from their egress
	// FIFO queue or drop decoy message.
	LambdaM float64

	// LambdaMMaxDelay sets the maximum delay for LambdaP.
	LambdaMMaxDelay uint64
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
	// LinkPublicKeyPem is string containing the PEM format of the peer's public link layer key.
	LinkPublicKey wire.PublicKey
	// Addresses are the IP address/port combinations that the peer authority
	// uses for the Directory Authority service.
	Addresses []string
}

// UnmarshalTOML deserializes into non-nil instances of sign.PublicKey and wire.PublicKey
func (a *Authority) UnmarshalTOML(v interface{}) error {
	_, a.IdentityPublicKey = cert.Scheme.NewKeypair()
	_, a.LinkPublicKey = wire.DefaultScheme.GenerateKeypair(rand.Reader)

	data, _ := v.(map[string]interface{})
	a.Identifier, _ = data["Identifier"].(string)
	idPublicKeyString, _ := data["IdentityPublicKey"].(string)
	err := a.IdentityPublicKey.UnmarshalText([]byte(idPublicKeyString))
	if err != nil {
		return err
	}
	linkPublicKeyString, _ := data["LinkPublicKey"].(string)
	err = a.LinkPublicKey.UnmarshalText([]byte(linkPublicKeyString))
	if err != nil {
		return err
	}
	addresses := make([]string, 0)
	pos, _ := data["Addresses"]
	for _, addr := range pos.([]interface{}) {
		addresses = append(addresses, addr.(string))
	}
	a.Addresses = addresses
	return nil
}

// Validate parses and checks the Authority configuration.
func (a *Authority) Validate() error {
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
	section := "Mixes"
	if isProvider {
		section = "Providers"
		if n.Identifier == "" {
			return fmt.Errorf("config: %v: Node is missing Identifier", section)
		}
		var err error
		n.Identifier, err = idna.Lookup.ToASCII(n.Identifier)
		if err != nil {
			return fmt.Errorf("config: Failed to normalize Identifier: %v", err)
		}
	} else if n.Identifier != "" {
		return fmt.Errorf("config: %v: Node has Identifier set", section)
	}
	if n.IdentityPublicKeyPem == "" {
		return fmt.Errorf("config: %v: Node is missing IdentityPublicKeyPem", section)
	}
	return nil
}

type Server struct {
	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// Addresses are the IP address/port combinations that the server will bind
	// to for incoming connections.
	Addresses []string

	// DataDir is the absolute path to the server's state files.
	DataDir string
}

// Validate parses and checks the Server configuration.
func (sCfg *Server) validate() error {
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

	Mixes     []*Node
	Providers []*Node
	Topology  *Topology

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

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (cfg *Config) FixupAndValidate() error {

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

	allNodes := make([]*Node, 0, len(cfg.Mixes)+len(cfg.Providers))
	for _, v := range cfg.Mixes {
		allNodes = append(allNodes, v)
	}
	for _, v := range cfg.Providers {
		allNodes = append(allNodes, v)
	}
	_, identityKey := cert.Scheme.NewKeypair()
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

		err := pem.FromFile(filepath.Join(cfg.Server.DataDir, v.IdentityPublicKeyPem), identityKey)
		if err != nil {
			return err
		}

		tmp := identityKey.Sum256()
		if _, ok := pkMap[tmp]; ok {
			return fmt.Errorf("config: Nodes: IdentityPublicKeyPem '%v' is present more than once", v.IdentityPublicKeyPem)
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
	ourPubKey := cert.Scheme.NewEmptyPublicKey()
	err = ourPubKey.UnmarshalText(pemData)
	if err != nil {
		return err
	}
	ourPubKeyHash := ourPubKey.Sum256()
	for _, auth := range cfg.Authorities {
		err := auth.Validate()
		if err != nil {
			return err
		}
		if auth.IdentityPublicKey.Sum256() == ourPubKeyHash {
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
	if err := cfg.FixupAndValidate(); err != nil {
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
