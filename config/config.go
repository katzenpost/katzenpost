// config.go - Katzenpost client configuration.
// Copyright (C) 2018  Yawning Angel, David Stainton.
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

// Package config implements the configuration for the Katzenpost client.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/mail"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	nvClient "github.com/katzenpost/authority/nonvoting/client"
	"github.com/katzenpost/client/internal/proxy"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"golang.org/x/net/idna"
	"golang.org/x/text/secure/precis"
)

const (
	defaultLogLevel = "NOTICE"
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Proxy is the proxy configuration.
type Proxy struct {
	// DataDir is the absolute path to the data directory.
	DataDir string
}

func (pCfg *Proxy) validate() error {
	if !filepath.IsAbs(pCfg.DataDir) {
		return fmt.Errorf("config: Proxy: DataDir '%v' is not an absolute path", pCfg.DataDir)
	}
	return nil
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
		lCfg.Level = defaultLogLevel
	default:
		return fmt.Errorf("config: Logging: Level '%v' is invalid", lCfg.Level)
	}
	lCfg.Level = lvl // Force uppercase.
	return nil
}

// Debug is the debug configuration.
type Debug struct {
	// EnableLoops if set to true enables using client loop decoy
	// traffic.
	EnableLoops bool

	// LambdaL is the inverse of the mean of the exponential distribution
	// that is used to determine time duration between sending client
	// loop decoy traffic messages.
	LambdaL float64

	// LambdaLMaxInterval is the maximum value that can be produced using LambdaL
	// poisson process
	LambdaLMax uint64

	// LambdaLShift is the shift applied to the Lambda-L samples in
	// milliseconds.
	LambdaLShift uint64

	// LambdaD is the inverse of the mean of the exponential distribution
	// that is used to determine time duration between sending client
	// drop decoy traffic messages.
	LambdaD float64

	// LambdaDMaxInterval is the maximum value that can be produced using LambdaD
	// poisson process
	LambdaDMax uint64

	// LambdaLShift is the shift applied to the Lambda-L samples in
	// milliseconds.
	LambdaDShift uint64

	// CaseSensitiveUserIdentifiers disables the forced lower casing of
	// the Account `User` field.
	CaseSensitiveUserIdentifiers bool

	// GenerateOnly halts and cleans up right after long term
	// key generation.
	GenerateOnly bool

	// PollingInterval is the interval in seconds that will be used to
	// poll the receive queue.  By default this is 30 seconds.  Reducing
	// the value too far WILL result in uneccesary Provider load, and
	// increasing the value too far WILL adversely affect large message
	// transmit performance.
	PollingInterval int
}

// NonvotingAuthority is a non-voting authority configuration.
type NonvotingAuthority struct {
	// Address is the IP address/port combination of the authority.
	Address string

	// PublicKey is the authority's public key.
	PublicKey *eddsa.PublicKey
}

// New constructs a pki.Client with the specified non-voting authority config.
func (nvACfg *NonvotingAuthority) New(l *log.Backend, pCfg *proxy.Config) (pki.Client, error) {
	cfg := &nvClient.Config{
		LogBackend:    l,
		Address:       nvACfg.Address,
		PublicKey:     nvACfg.PublicKey,
		DialContextFn: pCfg.ToDialContext("nonvoting:" + nvACfg.PublicKey.String()),
	}
	return nvClient.New(cfg)
}

func (nvACfg *NonvotingAuthority) validate() error {
	if err := utils.EnsureAddrIPPort(nvACfg.Address); err != nil {
		return fmt.Errorf("Address '%v' is invalid: %v", nvACfg.Address, err)
	}
	if nvACfg.PublicKey == nil {
		return fmt.Errorf("PublicKey is missing")
	}
	return nil
}

// Account is a provider account configuration.
type Account struct {
	// User is the account user name.
	User string

	// Provider is the provider identifier used by this account.
	Provider string

	// ProviderKeyPin is the optional pinned provider signing key.
	ProviderKeyPin *eddsa.PublicKey
}

func (accCfg *Account) fixup(cfg *Config) error {
	var err error
	if !cfg.Debug.CaseSensitiveUserIdentifiers {
		accCfg.User, err = precis.UsernameCaseMapped.String(accCfg.User)
	} else {
		accCfg.User, err = precis.UsernameCasePreserved.String(accCfg.User)
	}
	if err != nil {
		return err
	}

	accCfg.Provider, err = idna.Lookup.ToASCII(accCfg.Provider)
	return err
}

func (accCfg *Account) toEmailAddr() (string, error) {
	addr := fmt.Sprintf("%s@%s", accCfg.User, accCfg.Provider)
	if _, err := mail.ParseAddress(addr); err != nil {
		return "", fmt.Errorf("User/Provider does not form a valid e-mail address: %v", err)
	}
	return addr, nil
}

func (accCfg *Account) validate(cfg *Config) error {
	if accCfg.User == "" {
		return fmt.Errorf("User is missing")
	}
	if accCfg.Provider == "" {
		return fmt.Errorf("Provider is missing")
	}
	return nil
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

// Config is the top level client configuration.
type Config struct {
	Proxy              *Proxy
	Logging            *Logging
	UpstreamProxy      *UpstreamProxy
	Debug              *Debug
	NonvotingAuthority *NonvotingAuthority
	Account            *Account
	upstreamProxy      *proxy.Config
}

// UpstreamProxyConfig returns the configured upstream proxy, suitable for
// internal use.  Most people should not use this.
func (cfg *Config) UpstreamProxyConfig() *proxy.Config {
	return cfg.upstreamProxy
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (cfg *Config) FixupAndValidate() error {
	// Handle missing sections if possible.
	if cfg.Proxy == nil {
		return errors.New("config: No Proxy block was present")
	}
	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}
	if cfg.Debug == nil {
		cfg.Debug = &Debug{}
	}

	// Validate/fixup the various sections.
	if err := cfg.Proxy.validate(); err != nil {
		return err
	}
	if err := cfg.Logging.validate(); err != nil {
		return err
	}
	if uCfg, err := cfg.UpstreamProxy.toProxyConfig(); err != nil {
		return err
	} else {
		cfg.upstreamProxy = uCfg
	}
	if err := cfg.NonvotingAuthority.validate(); err != nil {
		return fmt.Errorf("config: NonvotingAuthority is invalid: %s", err)
	}

	// account
	if err := cfg.Account.fixup(cfg); err != nil {
		return fmt.Errorf("config: Account is invalid (User): %v", err)
	}
	addr, err := cfg.Account.toEmailAddr()
	if err != nil {
		return fmt.Errorf("config: Account is invalid (Identifier): %v", err)
	}
	if err := cfg.Account.validate(cfg); err != nil {
		return fmt.Errorf("config: Account '%v' is invalid: %v", addr, err)
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

// LoadFile loads, parses, and validates the provided file and returns the
// Config.
func LoadFile(f string, forceGenOnly bool) (*Config, error) {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b, forceGenOnly)
}
