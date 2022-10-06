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
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/idna"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
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

// Authority is the authority configuration.
type Authority struct {
	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// Addresses are the IP address/port combinations that the authority will
	// bind to for incoming connections.
	Addresses []string

	// DataDir is the absolute path to the authority's state files.
	DataDir string
}

// Validate parses and checks the Authority configuration.
func (sCfg *Authority) validate() error {
	if sCfg.Addresses != nil {
		for _, v := range sCfg.Addresses {
			if err := utils.EnsureAddrIPPort(v); err != nil {
				return fmt.Errorf("config: Authority: Address '%v' is invalid: %v", v, err)
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

// AuthorityPeer is the connecting information
// and identity key for the Authority peers
type AuthorityPeer struct {
	// IdentityPublicKeyPem is the full file path and filename
	// containing the PEM file of the peer's identity signing key.
	IdentityPublicKeyPem string
	// LinkPublicKeyPem is the full file path and filename
	// containing the PEM of the peer's public link layer key.
	LinkPublicKeyPem string
	// Addresses are the IP address/port combinations that the peer authority
	// uses for the Directory Authority service.
	Addresses []string
}

// Validate parses and checks the AuthorityPeer configuration.
func (a *AuthorityPeer) Validate(datadir string) error {
	for _, v := range a.Addresses {
		if err := utils.EnsureAddrIPPort(v); err != nil {
			return fmt.Errorf("config: AuthorityPeer: Address '%v' is invalid: %v", v, err)
		}
	}
	if a.IdentityPublicKeyPem == "" {
		return fmt.Errorf("config: %v: AuthorityPeer is missing Identity Key", a)
	}

	if a.LinkPublicKeyPem == "" {
		return fmt.Errorf("config: %v: AuthorityPeer is missing Link Key PEM filename", a)
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

// Config is the top level authority configuration.
type Config struct {
	Authority   *Authority
	Authorities []*AuthorityPeer
	Logging     *Logging
	Parameters  *Parameters
	Debug       *Debug

	Mixes     []*Node
	Providers []*Node
	Topology  *Topology
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
	// Handle missing sections if possible.
	if cfg.Authority == nil {
		return errors.New("config: No Authority block was present")
	}
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
	if err := cfg.Authority.validate(); err != nil {
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
		if err := v.validate(false); err != nil {
			return err
		}
		allNodes = append(allNodes, v)
	}
	idMap := make(map[string]*Node)
	for _, v := range cfg.Providers {
		if err := v.validate(true); err != nil {
			return err
		}
		if _, ok := idMap[v.Identifier]; ok {
			return fmt.Errorf("config: Providers: Identifier '%v' is present more than once", v.Identifier)
		}
		idMap[v.Identifier] = v
		allNodes = append(allNodes, v)
	}
	_, identityKey := cert.Scheme.NewKeypair()
	pkMap := make(map[[publicKeyHashSize]byte]*Node)
	for _, v := range allNodes {
		err := pem.FromFile(filepath.Join(cfg.Authority.DataDir, v.IdentityPublicKeyPem), identityKey)
		if err != nil {
			return err
		}

		tmp := identityKey.Sum256()
		if _, ok := pkMap[tmp]; ok {
			return fmt.Errorf("config: Nodes: IdentityPublicKeyPem '%v' is present more than once", v.IdentityPublicKeyPem)
		}
		pkMap[tmp] = v
	}

	for _, auth := range cfg.Authorities {
		err := auth.Validate(cfg.Authority.DataDir)
		if err != nil {
			return err
		}
	}

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte, forceGenOnly bool) (*Config, error) {
	cfg := new(Config)
	md, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("config: Undecoded keys in config file: %v", undecoded)
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
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b, forceGenOnly)
}
