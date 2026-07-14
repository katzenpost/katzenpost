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

//go:build !wasm

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

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/hpqc/hash"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/utils"
)

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

	if a.LinkPublicKey.PublicKey == nil {
		return fmt.Errorf("config: %v: Authority is missing Link Key PEM filename", a)
	}

	return nil
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
	linkPubKey, err := kempem.FromPublicPEMString(linkPublicKeyString, s)
	if err != nil {
		return err
	}
	a.LinkPublicKey = LinkPublicKey{PublicKey: linkPubKey}

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

// Validate parses and checks the Server configuration.
func (sCfg *Server) validate() error {
	// Set timeout defaults if not specified
	if sCfg.DialTimeoutSec == 0 {
		sCfg.DialTimeoutSec = 30
	}
	if sCfg.HandshakeTimeoutSec == 0 {
		sCfg.HandshakeTimeoutSec = 3
	}
	if sCfg.ResponseTimeoutSec == 0 {
		sCfg.ResponseTimeoutSec = 30
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
		if err := utils.RejectDNSAddrs(sCfg.Addresses, sCfg.AllowHostnameAddresses); err != nil {
			return fmt.Errorf("config: Authority Server Addresses: %w", err)
		}
		if err := utils.RejectDNSAddrs(sCfg.BindAddresses, sCfg.AllowHostnameAddresses); err != nil {
			return fmt.Errorf("config: Authority Server BindAddresses: %w", err)
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
	if sCfg.MetricsAddress != "" {
		if err := utils.RejectDNSMetricsAddr(sCfg.MetricsAddress, sCfg.AllowHostnameAddresses); err != nil {
			return fmt.Errorf("config: Authority Server: %w", err)
		}
	}
	if !filepath.IsAbs(sCfg.DataDir) {
		return fmt.Errorf("config: Authority: DataDir '%v' is not an absolute path", sCfg.DataDir)
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
	// Refuse DNS hostnames in peer-authority Addresses unless the
	// operator explicitly opted in (docker-mixnet). Authority.Validate
	// already checked URL well-formedness; this loop applies the
	// no-DNS-in-production policy across every authority entry.
	for _, auth := range cfg.Authorities {
		if err := utils.RejectDNSAddrs(auth.Addresses, cfg.Server.AllowHostnameAddresses); err != nil {
			return fmt.Errorf("config: Authority %q: %w", auth.Identifier, err)
		}
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

	replicaIdMap := make(map[string]*StorageReplicaNode)
	replicaPkMap := make(map[[publicKeyHashSize]byte]*StorageReplicaNode)
	replicaIDSet := make(map[uint8]*StorageReplicaNode)
	for _, v := range cfg.StorageReplicas {
		if _, ok := replicaIdMap[v.Identifier]; ok {
			return fmt.Errorf("config: Storage Replica Node: Identifier '%v' is present more than once", v.Identifier)
		}
		if err := v.validate(); err != nil {
			return err
		}
		replicaIdMap[v.Identifier] = v

		// Validate unique ReplicaIDs
		if existing, ok := replicaIDSet[v.ReplicaID]; ok {
			return fmt.Errorf("config: Storage Replica Node: ReplicaID '%v' is used by both '%v' and '%v'", v.ReplicaID, existing.Identifier, v.Identifier)
		}
		replicaIDSet[v.ReplicaID] = v

		identityKey, err = signpem.FromPublicPEMFile(filepath.Join(cfg.Server.DataDir, v.IdentityPublicKeyPem), pkiSignatureScheme)
		if err != nil {
			return err
		}

		tmp := hash.Sum256From(identityKey)
		if _, ok := replicaPkMap[tmp]; ok {
			return fmt.Errorf("config: Storage Replica Node: IdentityPublicKeyPem '%v' is present more than once", v.IdentityPublicKeyPem)
		}
		replicaPkMap[tmp] = v
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
