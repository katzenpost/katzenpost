// config.go - Katzenpost non-voting authority server configuration.
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

// Package config implements the Katzenpost non-voting authority server
// configuration.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
	"github.com/pelletier/go-toml"
)

const (
	defaultAddress          = ":62472"
	defaultLogLevel         = "NOTICE"
	defaultLayers           = 3
	defaultMinNodesPerLayer = 2
	absoluteMaxDelay        = 6 * 60 * 60 * 1000 // 6 hours.

	// Note: These values are picked primarily for debugging and need to
	// be changed to something more suitable for a production deployment
	// at some point.
	defaultLambda        = 0.00025
	defaultMaxPercentile = 0.99999
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Authority is the authority configuration.
type Authority struct {
	// Addresses are the IP address/port combinations that the authority will
	// bind to for incoming connections.
	Addresses []string

	// DataDir is the absolute path to the authority's state files.
	DataDir string
}

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
	// Lambda is the inverse of the mean of the exponential distribution that
	// clients will use to sample delays.
	Lambda float64

	// MaxDelay is the maximum per-hop delay in milliseconds.
	MaxDelay uint64
}

func (pCfg *Parameters) validate() error {
	if pCfg.Lambda < 0 {
		return fmt.Errorf("config: Parameters: Lambda %v is invalid", pCfg.Lambda)
	}
	if pCfg.MaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: MaxDelay %v is out of range", pCfg.MaxDelay)
	}
	return nil
}

func (pCfg *Parameters) applyDefaults() {
	if pCfg.Lambda == 0 {
		pCfg.Lambda = defaultLambda
	}
	if pCfg.MaxDelay == 0 {
		pCfg.MaxDelay = uint64(rand.ExpQuantile(pCfg.Lambda, defaultMaxPercentile))
		if pCfg.MaxDelay > absoluteMaxDelay {
			pCfg.MaxDelay = absoluteMaxDelay
		}
	}
}

// Debug is the authority debug configuration.
type Debug struct {
	// ForceIdentityKey specifies a hex encoded identity private key.
	ForceIdentityKey string

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

// Node is an authority mix node or provider entry.
type Node struct {
	// Identifier is the human readable node identifier, to be set iff
	// the node is a Provider.
	Identifier string

	// IdentityKey is the node's identity signing key.
	IdentityKey *eddsa.PublicKey
}

func (n *Node) validate(isProvider bool) error {
	section := "Mixes"
	if isProvider {
		section = "Providers"
		if n.Identifier == "" {
			return fmt.Errorf("config: %v: Node is missing Identifier", section)
		}
		if len(n.Identifier) > constants.NodeIDLength {
			return fmt.Errorf("config: %v: Identifier '%v' exceeds max length", section, n.Identifier)
		}
	} else if n.Identifier != "" {
		return fmt.Errorf("config: %v: Node has Identifier set", section)
	}
	if n.IdentityKey == nil {
		return fmt.Errorf("config: %v: Node is missing IdentityKey", section)
	}
	return nil
}

// Config is the top level authority configuration.
type Config struct {
	Authority  *Authority
	Logging    *Logging
	Parameters *Parameters
	Debug      *Debug

	Mixes     []*Node
	Providers []*Node
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
	pkMap := make(map[[eddsa.PublicKeySize]byte]*Node)
	for _, v := range allNodes {
		var tmp [eddsa.PublicKeySize]byte
		copy(tmp[:], v.IdentityKey.Bytes())
		if _, ok := pkMap[tmp]; ok {
			return fmt.Errorf("config: Nodes: IdentityKey '%v' is present more than once", v.IdentityKey)
		}
		pkMap[tmp] = v
	}

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	// The TOML library that's being used is too dumb to unmarshal sub-structs,
	// so, do this the hard way.
	tree, err := toml.LoadBytes(b)
	if err != nil {
		return nil, err
	}

	cfg := new(Config)

	// Handle all the sections that *can* be Unmarshaled.
	if authTree, ok := tree.Get("Authority").(*toml.Tree); ok {
		cfg.Authority = new(Authority)
		if err := authTree.Unmarshal(cfg.Authority); err != nil {
			return nil, err
		}
	}
	if logTree, ok := tree.Get("Logging").(*toml.Tree); ok {
		cfg.Logging = new(Logging)
		if err := logTree.Unmarshal(cfg.Logging); err != nil {
			return nil, err
		}
	}
	if paramTree, ok := tree.Get("Parameters").(*toml.Tree); ok {
		cfg.Parameters = new(Parameters)
		if err := paramTree.Unmarshal(cfg.Parameters); err != nil {
			return nil, err
		}
	}
	if debugTree, ok := tree.Get("Debug").(*toml.Tree); ok {
		cfg.Debug = new(Debug)
		if err := debugTree.Unmarshal(cfg.Parameters); err != nil {
			return nil, err
		}
	}

	unmarshalNodeArray := func(key string) ([]*Node, error) {
		const (
			tomlID  = "Identifier"
			tomlKey = "IdentityKey"
		)

		trees, ok := tree.Get(key).([]*toml.Tree)
		if !ok {
			return nil, fmt.Errorf("missing Node array %v", key)
		}
		ret := make([]*Node, 0, len(trees))
		for _, tree := range trees {
			n := new(Node)
			if rawID := tree.Get(tomlID); rawID != nil {
				s, ok := rawID.(string)
				if !ok {
					pos := tree.GetPosition(tomlID)
					return nil, fmt.Errorf("%v: failed to parse Identifier", pos)
				}
				n.Identifier = s
			}

			if rawKey := tree.Get(tomlKey); rawKey != nil {
				n.IdentityKey = new(eddsa.PublicKey)
				s := rawKey.(string)
				if err := n.IdentityKey.UnmarshalText([]byte(s)); err != nil {
					pos := tree.GetPosition(tomlKey)
					return nil, fmt.Errorf("%v: failed to parse IdentityKey: %v", pos, err)
				}
			}
			ret = append(ret, n)
		}
		return ret, nil
	}

	// Unmarshal the Mixes and Provider arrays by hand.
	if cfg.Mixes, err = unmarshalNodeArray("Mixes"); err != nil {
		return nil, err
	}
	if cfg.Providers, err = unmarshalNodeArray("Providers"); err != nil {
		return nil, err
	}

	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
