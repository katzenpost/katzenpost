// config.go - Katzenpost server configuration.
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

// Package config provides the Katzenpost server configuration.
package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
	"github.com/pelletier/go-toml"
)

const (
	defaultAddress          = ":3219"
	defaultLogLevel         = "NOTICE"
	defaultSchedulerSlack   = 10        // 10 ms.
	defaultSendSlack        = 50        // 50 ms.
	defaultConnectTimeout   = 60 * 1000 // 60 sec.
	defaultHandshakeTimeout = 30 * 1000 // 30 sec.
	defaultReauthInterval   = 30 * 1000 // 30 sec.
	defaultUserDB           = "users.db"
	defaultSpoolDB          = "spool.db"
	defaultManagementSocket = "management_sock"
)

var defaultLogging = Logging{
	Disable: false,
	File:    "",
	Level:   defaultLogLevel,
}

// Server is the Katzenpost server configuration.
type Server struct {
	// Identifier is the human readable identifier for the node (eg: FQDN).
	Identifier string

	// Addresses are the IP address/port combinations that the server will bind
	// to for incoming connections.
	Addresses []string

	// DataDir is the absolute path to the server's state files.
	DataDir string

	// IsProvider specifies if the server is a provider (vs a mix).
	IsProvider bool
}

func (sCfg *Server) validate() error {
	if sCfg.Identifier == "" {
		return fmt.Errorf("config: Server: Identifier is not set")
	} else if len(sCfg.Identifier) > constants.NodeIDLength {
		return fmt.Errorf("config: Server: Identifier '%v' exceeds max length", sCfg.Identifier)
	}

	if sCfg.Addresses != nil {
		for _, v := range sCfg.Addresses {
			if err := utils.EnsureAddrIPPort(v); err != nil {
				return fmt.Errorf("config: Server: Address '%v' is invalid: %v", v, err)
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
		return fmt.Errorf("config: Server: DataDir '%v' is not an absolute path", sCfg.DataDir)
	}
	return nil
}

// Debug is the Katzenpost server debug configuration.
type Debug struct {
	// ForceIdentityKey specifies a hex encoded identity private key.
	ForceIdentityKey string

	// NumSphinxWorkers specifies the number of worker instances to use for
	// inbound Sphinx packet processing.
	NumSphinxWorkers int

	// SchedulerQueueSize is the maximum allowed scheduler queue size before
	// random entries will start getting dropped.  A value <= 0 is treated
	// as unlimited.
	SchedulerQueueSize int

	// SchedulerSlack is the maximum allowed scheduler slack due to queueing
	// and or processing in milliseconds.
	SchedulerSlack int

	// SendSlack is the maximum allowed send queue slack due to queueing and
	// or congestion in milliseconds.
	SendSlack int

	// ConnectTimeout specifies the maximum time a connection can take to
	// establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// HandshakeTimeout specifies the maximum time a connection can take for a
	// link protocol handshake in milliseconds.
	HandshakeTimeout int

	// ReauthInterval specifies the interval at which a connection will be
	// reauthenticated in milliseconds.
	ReauthInterval int

	// DisableKeyRotation disables the mix key rotation.
	DisableKeyRotation bool

	// DisableMixAuthentication disables the mix incoming peer authentication.
	DisableMixAuthentication bool

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool
}

// IsUnsafe returns true iff any debug options that destroy security are set.
func (dCfg *Debug) IsUnsafe() bool {
	return dCfg.ForceIdentityKey != "" || dCfg.DisableKeyRotation || dCfg.DisableMixAuthentication
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.NumSphinxWorkers <= 0 {
		// Pick a sane default for the number of workers.
		//
		// TODO/perf: This should detect the number of physical cores, since
		// the AES-NI unit is a per-core resource.
		dCfg.NumSphinxWorkers = runtime.NumCPU()
	}
	if dCfg.SchedulerSlack < defaultSchedulerSlack {
		// TODO/perf: Tune this.
		dCfg.SchedulerSlack = defaultSchedulerSlack
	}
	if dCfg.SendSlack < defaultSendSlack {
		// TODO/perf: Tune this, probably upwards to be more tollerant of poor
		// networking conditions.
		dCfg.SendSlack = defaultSendSlack
	}
	if dCfg.ConnectTimeout <= 0 {
		dCfg.ConnectTimeout = defaultConnectTimeout
	}
	if dCfg.HandshakeTimeout <= 0 {
		dCfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if dCfg.ReauthInterval <= 0 {
		dCfg.ReauthInterval = defaultReauthInterval
	}
}

// Logging is the Katzenpost server logging configuration.
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

// Provider is the Katzenpost provider configuration.
type Provider struct {
	// UserDB is the path to the user database.  If left empty it will use
	// `users.db` under the DataDir.
	UserDB string

	// SpoolDB is the path to the user message spool.  If left empty, it will
	// use `spool.db` under the DataDir.
	SpoolDB string
}

func (pCfg *Provider) applyDefaults(sCfg *Server) {
	if pCfg.UserDB == "" {
		pCfg.UserDB = filepath.Join(sCfg.DataDir, defaultUserDB)
	}
	if pCfg.SpoolDB == "" {
		pCfg.SpoolDB = filepath.Join(sCfg.DataDir, defaultSpoolDB)
	}
}

func (pCfg *Provider) validate() error {
	if !filepath.IsAbs(pCfg.UserDB) {
		return fmt.Errorf("config: Provider: UserDB '%v' is not an absolute path", pCfg.UserDB)
	}
	if !filepath.IsAbs(pCfg.SpoolDB) {
		return fmt.Errorf("config: Provider: SpoolDB '%v' is not an absolute path", pCfg.SpoolDB)
	}
	return nil
}

// PKI is the Katzenpost directory authority configuration.
type PKI struct {
	// Nonvoting is a non-voting directory authority.
	Nonvoting *Nonvoting
}

func (pCfg *PKI) validate() error {
	nrCfg := 0
	if pCfg.Nonvoting != nil {
		if err := pCfg.Nonvoting.validate(); err != nil {
			return err
		}
		nrCfg++
	}
	if nrCfg != 1 {
		return fmt.Errorf("config: Only one authority backend should be configured, got: %v", nrCfg)
	}
	return nil
}

// Nonvoting is a non-voting directory authority.
type Nonvoting struct {
	// Address is the authority's IP/port combination.
	Address string

	// PublicKey is the authority's public key in Base64 or Base16 format.
	PublicKey string
}

func (nCfg *Nonvoting) validate() error {
	if err := utils.EnsureAddrIPPort(nCfg.Address); err != nil {
		return fmt.Errorf("config: PKI/Nonvoting: Address is invalid: %v", err)
	}

	var pubKey eddsa.PublicKey
	if err := pubKey.FromString(nCfg.PublicKey); err != nil {
		return fmt.Errorf("config: PKI/Nonvoting: Invalid PublicKey: %v", err)
	}

	return nil
}

// Management is the Katzenpost management interface configuration.
type Management struct {
	// Enable enables the management interface.
	Enable bool

	// Path specifies the path to the manaagment interface socket.  If left
	// empty it will use `management_sock` under the DataDir.
	Path string
}

func (mCfg *Management) applyDefaults(sCfg *Server) {
	if mCfg.Path == "" {
		mCfg.Path = filepath.Join(sCfg.DataDir, defaultManagementSocket)
	}
}

func (mCfg *Management) validate() error {
	if !mCfg.Enable {
		return nil
	}
	if !filepath.IsAbs(mCfg.Path) {
		return fmt.Errorf("config: Management: Path '%v' is not an absolute path", mCfg.Path)
	}
	return nil
}

// Config is the top level Katzenpost server configuration.
type Config struct {
	Server     *Server
	Logging    *Logging
	Provider   *Provider
	PKI        *PKI
	Management *Management

	Debug *Debug
}

// FixupAndValidate applies defaults to config entries and validates the
// supplied configuration.  Most people should call one of the Load variants
// instead.
func (cfg *Config) FixupAndValidate() error {
	// The Server and PKI sections are mandatory, everything else is optional.
	if cfg.Server == nil {
		return errors.New("config: No Server block was present")
	}
	if cfg.Debug == nil {
		cfg.Debug = &Debug{}
	}
	if cfg.Logging == nil {
		cfg.Logging = &defaultLogging
	}
	if cfg.PKI == nil {
		return errors.New("config: No PKI block was present")
	}
	if cfg.Management == nil {
		cfg.Management = &Management{}
	}

	// Perform basic validation.
	if err := cfg.Server.validate(); err != nil {
		return err
	}
	if err := cfg.PKI.validate(); err != nil {
		return err
	}
	if cfg.Server.IsProvider {
		if cfg.Debug.DisableMixAuthentication {
			return errors.New("config: DisableMixAuthentication set when not a Mix")
		}

		if cfg.Provider == nil {
			cfg.Provider = &Provider{}
		}
		cfg.Provider.applyDefaults(cfg.Server)
		if err := cfg.Provider.validate(); err != nil {
			return err
		}
	} else if cfg.Provider != nil {
		return errors.New("config: Provider block set when not a Provider")
	}
	if err := cfg.Logging.validate(); err != nil {
		return err
	}
	cfg.Management.applyDefaults(cfg.Server)
	if err := cfg.Management.validate(); err != nil {
		return err
	}
	cfg.Debug.applyDefaults()

	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	cfg := new(Config)
	if err := toml.Unmarshal(b, cfg); err != nil {
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
