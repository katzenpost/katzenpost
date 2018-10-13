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

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
	"golang.org/x/net/idna"
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
	defaultMixLambda        = 0.00025
	defaultMixMaxPercentile = 0.99999

	// rate limiting of client connections
	defaultSendRatePerMinute = 100

	defaultSendLambda        = 0.00006
	defaultSendMaxPercentile = 0.95
	defaultDropLambda        = 0.00006
	defaultDropMaxPercentile = 0.95
	defaultLoopLambda        = 0.00006
	defaultLoopMaxPercentile = 0.95
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
	// SendRatePerMinute is the rate per minute.
	SendRatePerMinute uint64

	// MixLambda is the inverse of the mean of the exponential distribution
	// that the Sphinx packet per-hop mixing delay will be sampled from.
	MixLambda float64

	// MixMaxDelay is the maximum Sphinx packet per-hop mixing delay in
	// milliseconds.
	MixMaxDelay uint64

	// SendLambda is the inverse of the mean of the exponential distribution
	// that clients will sample to determine send timing legit forward messages
	// or drop decoy messages.
	SendLambda float64

	// SendMaxInterval is the maximum send interval in milliseconds, enforced
	// prior to (excluding) SendShift.
	SendMaxInterval uint64

	// DropLambda is the inverse of the mean of the exponential distribution
	// that clients will sample to determine send timing of drop decoy messages.
	DropLambda float64

	// DropMaxInterval is the maximum send interval in milliseconds, enforced
	// prior to (excluding) DropShift.
	DropMaxInterval uint64

	// LoopLambda is the inverse of the mean of the exponential distribution
	// that clients will sample to determine send timing of loop decoy messages.
	LoopLambda float64

	// LoopMaxInterval is the maximum send interval in milliseconds, enforced
	// prior to (excluding) LoopShift.
	LoopMaxInterval uint64
}

func (pCfg *Parameters) validate() error {
	if pCfg.MixLambda < 0 {
		return fmt.Errorf("config: Parameters: MixLambda %v is invalid", pCfg.MixLambda)
	}
	if pCfg.MixMaxDelay > absoluteMaxDelay {
		return fmt.Errorf("config: Parameters: MixMaxDelay %v is out of range", pCfg.MixMaxDelay)
	}
	if pCfg.SendLambda < 0 {
		return fmt.Errorf("config: Parameters: SendLambda %v is invalid", pCfg.SendLambda)
	}
	return nil
}

func (pCfg *Parameters) applyDefaults() {
	if pCfg.MixLambda == 0 {
		pCfg.MixLambda = defaultMixLambda
	}
	if pCfg.MixMaxDelay == 0 {
		pCfg.MixMaxDelay = uint64(rand.ExpQuantile(pCfg.MixLambda, defaultMixMaxPercentile))
		if pCfg.MixMaxDelay > absoluteMaxDelay {
			pCfg.MixMaxDelay = absoluteMaxDelay
		}
	}
	if pCfg.SendLambda == 0 {
		pCfg.SendLambda = defaultSendLambda
	}
	if pCfg.SendRatePerMinute == 0 {
		pCfg.SendRatePerMinute = defaultSendRatePerMinute
	}
	if pCfg.SendMaxInterval == 0 {
		pCfg.SendMaxInterval = uint64(rand.ExpQuantile(pCfg.SendLambda, defaultSendMaxPercentile))
	}
	if pCfg.DropLambda == 0 {
		pCfg.DropLambda = defaultDropLambda
	}
	if pCfg.DropMaxInterval == 0 {
		pCfg.DropMaxInterval = uint64(rand.ExpQuantile(pCfg.DropLambda, defaultDropMaxPercentile))
	}
	if pCfg.LoopLambda == 0 {
		pCfg.LoopLambda = defaultLoopLambda
	}
	if pCfg.LoopMaxInterval == 0 {
		pCfg.LoopMaxInterval = uint64(rand.ExpQuantile(pCfg.LoopLambda, defaultLoopMaxPercentile))
	}
}

// Debug is the authority debug configuration.
type Debug struct {
	// IdentityKey specifies the identity private key.
	IdentityKey *eddsa.PrivateKey `toml:"-"`

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
		var err error
		n.Identifier, err = idna.Lookup.ToASCII(n.Identifier)
		if err != nil {
			return fmt.Errorf("config: Failed to normalize Identifier: %v", err)
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
