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
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/utils"
	"golang.org/x/net/idna"
	"golang.org/x/text/secure/precis"
)

const (
	defaultAddress            = ":3219"
	defaultLogLevel           = "NOTICE"
	defaultNumProviderWorkers = 1
	defaultUnwrapDelay        = 10 // 10 ms.
	defaultSchedulerSlack     = 10 // 10 ms.
	defaultSchedulerMaxBurst  = 16
	defaultSendSlack          = 50        // 50 ms.
	defaultDecoySlack         = 15 * 1000 // 15 sec.
	defaultConnectTimeout     = 60 * 1000 // 60 sec.
	defaultHandshakeTimeout   = 30 * 1000 // 30 sec.
	defaultReauthInterval     = 30 * 1000 // 30 sec.
	defaultProviderDelay      = 500       // 250 ms.
	defaultUserDB             = "users.db"
	defaultSpoolDB            = "spool.db"
	defaultManagementSocket   = "management_sock"

	backendPgx = "pgx"

	// BackendSQL is a SQL based backend.
	BackendSQL = "sql"

	// BackendBolt is a BoltDB based backend.
	BackendBolt = "bolt"

	// BackendExtern is a External (RESTful http) backend.
	BackendExtern = "extern"
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
	// IdentityKey specifies the identity private key.
	IdentityKey *eddsa.PrivateKey `toml:"-"`

	// NumSphinxWorkers specifies the number of worker instances to use for
	// inbound Sphinx packet processing.
	NumSphinxWorkers int

	// NumProviderWorkers specifies the number pf worker instances to use for
	// provider specific packet processing.
	NumProviderWorkers int

	// SchedulerExternalMemoryQueue will enable the experimental external
	// memory queue that is backed by disk.
	SchedulerExternalMemoryQueue bool

	// SchedulerQueueSize is the maximum allowed scheduler queue size before
	// random entries will start getting dropped.  A value <= 0 is treated
	// as unlimited.
	SchedulerQueueSize int

	// SchedulerMaxBurst is the maximum number of packets that will be
	// dispatched per scheduler wakeup event.
	SchedulerMaxBurst int

	// UnwrapDelay is the maximum allowed unwrap delay due to queueing in
	// milliseconds.
	UnwrapDelay int

	// ProviderDelay is the maximum allowed provider delay due to queueing
	// in milliseconds.
	ProviderDelay int

	// SchedulerSlack is the maximum allowed scheduler slack due to queueing
	// and or processing in milliseconds.
	SchedulerSlack int

	// SendSlack is the maximum allowed send queue slack due to queueing and
	// or congestion in milliseconds.
	SendSlack int

	// DecoySlack is the maximum allowed decoy sweep slack due to various
	// external delays such as latency before a loop decoy packet will
	// be considered lost.
	DecoySlack int

	// ConnectTimeout specifies the maximum time a connection can take to
	// establish a TCP/IP connection in milliseconds.
	ConnectTimeout int

	// HandshakeTimeout specifies the maximum time a connection can take for a
	// link protocol handshake in milliseconds.
	HandshakeTimeout int

	// ReauthInterval specifies the interval at which a connection will be
	// reauthenticated in milliseconds.
	ReauthInterval int

	// SendDecoyTraffic enables sending decoy traffic.  This is still
	// experimental and untuned and thus is disabled by default.
	//
	// WARNING: This option will go away once decoy traffic is more concrete.
	SendDecoyTraffic bool

	// GenerateOnly halts and cleans up the server right after long term
	// key generation.
	GenerateOnly bool
}

// IsUnsafe returns true iff any debug options that destroy security are set.
func (dCfg *Debug) IsUnsafe() bool {
	return dCfg.IdentityKey != nil
}

func (dCfg *Debug) applyDefaults() {
	if dCfg.NumSphinxWorkers <= 0 {
		// Pick a sane default for the number of workers.
		//
		// TODO/perf: This should detect the number of physical cores, since
		// the AES-NI unit is a per-core resource.
		dCfg.NumSphinxWorkers = runtime.NumCPU()
	}
	if dCfg.NumProviderWorkers <= 0 {
		// TODO/perf: This should do something clever as well, though 1 is
		// the right number for something that uses the boltspool due to all
		// write spool operations being serialized.
		dCfg.NumProviderWorkers = defaultNumProviderWorkers
	}
	if dCfg.UnwrapDelay <= 0 {
		dCfg.UnwrapDelay = defaultUnwrapDelay
	}
	if dCfg.ProviderDelay <= 0 {
		dCfg.ProviderDelay = defaultProviderDelay
	}
	if dCfg.SchedulerSlack < defaultSchedulerSlack {
		// TODO/perf: Tune this.
		dCfg.SchedulerSlack = defaultSchedulerSlack
	}
	if dCfg.SchedulerMaxBurst <= 0 {
		dCfg.SchedulerMaxBurst = defaultSchedulerMaxBurst
	}
	if dCfg.SendSlack < defaultSendSlack {
		// TODO/perf: Tune this, probably upwards to be more tolerant of poor
		// networking conditions.
		dCfg.SendSlack = defaultSendSlack
	}
	if dCfg.DecoySlack <= 0 {
		dCfg.DecoySlack = defaultDecoySlack
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
	// AltAddresses is the map of extra transports and addresses at which
	// the Provider is reachable by clients.  The most useful alternative
	// transport is likely ("tcp") (`core/pki.TransportTCP`).
	AltAddresses map[string][]string

	// SQLDB is the SQL database backend configuration.
	SQLDB *SQLDB

	// UserDB is the userdb backend configuration.
	UserDB *UserDB

	// SpoolDB is the user message spool configuration.
	SpoolDB *SpoolDB

	// BinaryRecipients disables all Provider side recipient pre-processing,
	// including removing trailing `NUL` bytes, case normalization, and
	// delimiter support.
	BinaryRecipients bool

	// CaseSensitiveRecipients disables recipient case normalization.  If left
	// unset, all user names will be converted to lower case.
	CaseSensitiveRecipients bool

	// RecipientDelimiter is the set of characters that separates a user name
	// from it's extension (eg: `alice+foo`).
	RecipientDelimiter string

	// Kaetzchen is the list of configured Kaetzchen (auto-responder agents)
	// for this provider.
	Kaetzchen []*Kaetzchen
}

// SQLDB is the SQL database backend configuration.
type SQLDB struct {
	// Backend is the active database backend (driver).
	//
	//  - pgx: Postgresql.
	Backend string

	// DataSourceName is the SQL data source name or URI.  The format
	// of this parameter is dependent on the database driver being used.
	//
	//  - pgx: https://godoc.org/github.com/jackc/pgx#ParseConnectionString
	DataSourceName string
}

func (sCfg *SQLDB) validate() error {
	switch sCfg.Backend {
	case backendPgx:
	default:
		return fmt.Errorf("config: SQLDB: Backend '%v' is invalid", sCfg.Backend)
	}
	if sCfg.DataSourceName == "" {
		return fmt.Errorf("config: SQLDB: DataSourceName '%v' is invalid", sCfg.DataSourceName)
	}
	return nil
}

// UserDB is the userdb backend configuration.
type UserDB struct {
	// Backend is the active userdb backend.  If left empty, the BoltUserDB
	// backend will be used (`bolt`).
	Backend string

	// BoltDB backed userdb (`bolt`).
	Bolt *BoltUserDB

	// Externally defined (RESTful http) userdb (`extern`).
	Extern *ExternUserDB
}

// BoltUserDB is the BoltDB implementation of userdb.
type BoltUserDB struct {
	// UserDB is the path to the user database.  If left empty it will use
	// `users.db` under the DataDir.
	UserDB string
}

// ExternUserDB is the external http user authentication.
type ExternUserDB struct {
	// ProviderURL is the base url used for the external provider authentication API.
	// It should be in the form `http://localhost:8080/`
	ProviderURL string
}

// SpoolDB is the user message spool configuration.
type SpoolDB struct {
	// Backend is the active spool backend.  If left empty, the BoltSpoolDB
	// backend will be used (`bolt`).
	Backend string

	// BoltDB backed spool (`bolt`).
	Bolt *BoltSpoolDB
}

// BoltSpoolDB is the BolTDB implementation of the spool.
type BoltSpoolDB struct {
	// SpoolDB is the path to the user message spool.  If left empty, it will
	// use `spool.db` under the DataDir.
	SpoolDB string
}

// Kaetzchen is a Provider auto-responder agent.
type Kaetzchen struct {
	// Capability is the capability exposed by the agent.
	Capability string

	// Endpoint is the provider side endpoint that the agent will accept
	// requests at.  While not required by the spec, this server only
	// supports Endpoints that are lower-case local-parts of an e-mail
	// address.
	Endpoint string

	// Config is the extra per agent arguments to be passed to the agent's
	// initialization routine.
	Config map[string]interface{}

	// Disable disabled a configured agent.
	Disable bool
}

func (kCfg *Kaetzchen) validate() error {
	if kCfg.Capability == "" {
		return fmt.Errorf("config: Kaetzchen: Capability is invalid.")
	}

	// Ensure the endpoint is normalized.
	epNorm, err := precis.UsernameCaseMapped.String(kCfg.Endpoint)
	if err != nil {
		return fmt.Errorf("config: Kaetzchen: '%v' has invalid endpoint: %v", kCfg.Capability, err)
	}
	if epNorm != kCfg.Endpoint {
		return fmt.Errorf("config: Kaetzchen: '%v' has non-normalized endpoint %v", kCfg.Capability, kCfg.Endpoint)
	}
	if _, err = mail.ParseAddress(kCfg.Endpoint + "@test.invalid"); err != nil {
		return fmt.Errorf("config: Kaetzchen: '%v' has non local-part endpoint '%v': %v", kCfg.Capability, kCfg.Endpoint, err)
	}

	return nil
}

func (pCfg *Provider) applyDefaults(sCfg *Server) {
	if pCfg.AltAddresses == nil {
		pCfg.AltAddresses = make(map[string][]string)
	}
	if pCfg.UserDB == nil {
		pCfg.UserDB = &UserDB{}
	}
	if pCfg.UserDB.Backend == "" {
		pCfg.UserDB.Backend = BackendBolt
	}
	switch pCfg.UserDB.Backend {
	case BackendBolt:
		if pCfg.UserDB.Bolt == nil {
			pCfg.UserDB.Bolt = &BoltUserDB{}
		}
		if pCfg.UserDB.Bolt.UserDB == "" {
			pCfg.UserDB.Bolt.UserDB = filepath.Join(sCfg.DataDir, defaultUserDB)
		}
	default:
	}

	if pCfg.SpoolDB == nil {
		pCfg.SpoolDB = &SpoolDB{}
	}
	if pCfg.SpoolDB.Backend == "" {
		pCfg.SpoolDB.Backend = BackendBolt
	}
	switch pCfg.SpoolDB.Backend {
	case BackendBolt:
		if pCfg.SpoolDB.Bolt == nil {
			pCfg.SpoolDB.Bolt = &BoltSpoolDB{}
		}
		if pCfg.SpoolDB.Bolt.SpoolDB == "" {
			pCfg.SpoolDB.Bolt.SpoolDB = filepath.Join(sCfg.DataDir, defaultSpoolDB)
		}
	default:
	}
}

func (pCfg *Provider) validate() error {
	internalTransports := make(map[string]bool)
	for _, v := range pki.InternalTransports {
		internalTransports[strings.ToLower(string(v))] = true
	}

	for k, v := range pCfg.AltAddresses {
		kLower := strings.ToLower(k)
		if internalTransports[kLower] {
			return fmt.Errorf("config: Provider: AltAddress is overriding internal transport: %v", kLower)
		}
		switch pki.Transport(kLower) {
		case pki.TransportTCP:
			for _, a := range v {
				h, p, err := net.SplitHostPort(a)
				if err != nil {
					return fmt.Errorf("config: Provider: AltAddress '%v' is invalid: %v", a, err)
				}
				if len(h) == 0 {
					return fmt.Errorf("config: Provider: AltAddress '%v' is invalid: missing host", a)
				}
				if port, err := strconv.ParseUint(p, 10, 16); err != nil {
					return fmt.Errorf("config: Provider: AltAddress '%v' is invalid: %v", a, err)
				} else if port == 0 {
					return fmt.Errorf("config: Provider: AltAddress '%v' is invalid: missing port", a)
				}
			}
		default:
		}
	}

	if pCfg.SQLDB != nil {
		if err := pCfg.SQLDB.validate(); err != nil {
			return err
		}
	}

	switch pCfg.UserDB.Backend {
	case BackendBolt:
		if !filepath.IsAbs(pCfg.UserDB.Bolt.UserDB) {
			return fmt.Errorf("config: Provider: UserDB '%v' is not an absolute path", pCfg.UserDB.Bolt.UserDB)
		}
	case BackendExtern:
		if pCfg.UserDB.Extern == nil {
			return fmt.Errorf("config: Provider: Extern section should be defined")
		}
		if pCfg.UserDB.Extern.ProviderURL == "" {
			return fmt.Errorf("config: Provider: ProviderURL should be defined for Extern")
		}
		providerURL, err := url.Parse(pCfg.UserDB.Extern.ProviderURL)
		if err != nil {
			return fmt.Errorf("config: Provider: ProviderURL should be a valid url: %v", err)
		}
		switch providerURL.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("config: Provider: ProviderURL should be of http schema")
		}
	case BackendSQL:
		if pCfg.SQLDB == nil {
			return fmt.Errorf("config: Provider: UserDB configured for an SQL backend without a SQLDB block")
		}
	default:
		return fmt.Errorf("config: Provider: Invalid UserDB Backend: '%v'", pCfg.UserDB.Backend)
	}

	switch pCfg.SpoolDB.Backend {
	case BackendBolt:
		if !filepath.IsAbs(pCfg.SpoolDB.Bolt.SpoolDB) {
			return fmt.Errorf("config: Provider: SpoolDB '%v' is not an absolute path", pCfg.SpoolDB.Bolt.SpoolDB)
		}
	case BackendSQL:
		if pCfg.SQLDB == nil {
			return fmt.Errorf("config: Provider: SpoolDB configured for an SQL backend without a SQLDB block")
		}
	default:
		return fmt.Errorf("config: Provider: Invalid SpoolDB Backend: '%v'", pCfg.SpoolDB.Backend)
	}

	capaMap := make(map[string]bool)
	for _, v := range pCfg.Kaetzchen {
		if err := v.validate(); err != nil {
			return err
		}
		if capaMap[v.Capability] {
			return fmt.Errorf("config: Kaetzchen: '%v' configured multiple times", v.Capability)
		}
		capaMap[v.Capability] = true
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

	var err error
	cfg.Server.Identifier, err = idna.Lookup.ToASCII(cfg.Server.Identifier)
	if err != nil {
		return fmt.Errorf("config: Failed to normalize Identifier: %v", err)
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
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("config: Undecoded keys in config file: %v", undecoded)
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
