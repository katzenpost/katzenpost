// SPDX-FileCopyrightText: Copyright (C) 2018-2023  Yawning Angel, David Stainton.
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !thinclient

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/hpqc/kem/schemes"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/utils"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// PigeonholeGeometry derives the Pigeonhole geometry from the Sphinx geometry,
// the same derivation the courier and the storage replicas perform, so the
// client can never carry a geometry at odds with theirs. It is not stored on
// the config and is never read from the config file; a [PigeonholeGeometry]
// table in the file is rejected at load time. FixupAndValidate proves the
// derivation succeeds, so the panic here is unreachable for a loaded config.
func (c *Config) PigeonholeGeometry() *pigeonholeGeo.Geometry {
	derived, err := pigeonholeGeo.NewGeometryFromSphinx(c.SphinxGeometry, replicaCommon.NikeScheme)
	if err != nil {
		panic(fmt.Sprintf("config: cannot derive a Pigeonhole geometry from the SphinxGeometry: %v", err))
	}
	return derived
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
	if err := c.Listen.Validate(); err != nil {
		return err
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
	// Fail fast if the Sphinx geometry cannot yield a Pigeonhole geometry;
	// the daemon derives the Pigeonhole geometry from it at runtime via the
	// PigeonholeGeometry accessor.
	if _, err = pigeonholeGeo.NewGeometryFromSphinx(c.SphinxGeometry, replicaCommon.NikeScheme); err != nil {
		return fmt.Errorf("config: cannot derive a Pigeonhole geometry from the SphinxGeometry: %w", err)
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

	// Refuse DNS hostnames in client-side addresses unless the
	// operator explicitly opted in (docker-mixnet only). Covers
	// the Tcp listen subtable (Unix is exempt), the kpclientd
	// metrics listener, and every gateway / authority address the
	// client might dial. Onion addresses are always permitted.
	if c.Listen != nil && c.Listen.Tcp != nil {
		if err := utils.RejectDNSMetricsAddr(c.Listen.Tcp.Address, c.AllowHostnameAddresses); err != nil {
			return fmt.Errorf("config: Listen.Tcp.Address: %w", err)
		}
	}
	if err := utils.RejectDNSMetricsAddr(c.MetricsAddress, c.AllowHostnameAddresses); err != nil {
		return fmt.Errorf("config: MetricsAddress: %w", err)
	}
	if c.PinnedGateways != nil {
		for _, gw := range c.PinnedGateways.Gateways {
			if err := utils.RejectDNSAddrs(gw.Addresses, c.AllowHostnameAddresses); err != nil {
				return fmt.Errorf("config: PinnedGateway %q: %w", gw.Name, err)
			}
		}
	}
	if c.VotingAuthority != nil {
		for _, peer := range c.VotingAuthority.Peers {
			if err := utils.RejectDNSAddrs(peer.Addresses, c.AllowHostnameAddresses); err != nil {
				return fmt.Errorf("config: VotingAuthority peer %q: %w", peer.Identifier, err)
			}
		}
	}

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)

	md, err := toml.Decode(string(b), cfg)
	if err != nil {
		return nil, err
	}
	if err := rejectPigeonholeGeometry(md); err != nil {
		return nil, err
	}
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// rejectPigeonholeGeometry refuses a config that carries a
// [PigeonholeGeometry] table. The geometry is not a configuration field; it
// is derived from the Sphinx geometry. A table in the file is the stale-config
// failure mode that overflowed at send time, so it is refused outright rather
// than quietly ignored.
func rejectPigeonholeGeometry(md toml.MetaData) error {
	for _, key := range md.Undecoded() {
		if len(key) > 0 && key[0] == "PigeonholeGeometry" {
			return errors.New("config: [PigeonholeGeometry] must not be set; " +
				"it is derived from [SphinxGeometry]. Remove the [PigeonholeGeometry] table.")
		}
	}
	return nil
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
	linkKey, err := kempem.FromPublicPEMString(data["LinkKey"].(string), kemscheme)
	if err != nil {
		return err
	}
	p.LinkKey = LinkPublicKey{PublicKey: linkKey}

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

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
