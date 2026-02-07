// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

// Package genconfig generates Katzenpost mixnet configuration files ostensibly for testing.
// Currently the Katzenpost project uses this package as the main dependency for cmd/genconfig
// which is a CLI tool used by our docker mixnet setup.
package genconfig

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/common/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	rConfig "github.com/katzenpost/katzenpost/replica/config"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

const (
	BasePort               = 30000
	BindAddr               = "127.0.0.1"
	NrLayers               = 3
	NrNodes                = 6
	NrGateways             = 1
	NrServiceNodes         = 1
	NrStorageNodes         = 5
	NrAuthorities          = 3
	ServerLogFile          = "katzenpost.log"
	TcpAddrFormat          = "tcp://127.0.0.1:%d"
	IdentityPublicKeyFile  = "identity.public.pem"
	IdentityPrivateKeyFile = "identity.private.pem"
	LinkPublicKeyFile      = "link.public.pem"
	LinkPrivateKeyFile     = "link.private.pem"
	CourierService         = "courier"
	ClientIdentifier       = "client"
	Client2Identifier      = "client2"
	DebugLogLevel          = "DEBUG"
	AuthNodeFormat         = "auth%d"
	WritingLogFormat       = "writing %s"
)

// Config holds all the parsed command line flags
type Config struct {
	NrLayers                 int
	NrNodes                  int
	NrGateways               int
	NrServiceNodes           int
	NrStorageNodes           int
	Voting                   bool
	NrVoting                 int
	BaseDir                  string
	BasePort                 int
	BindAddr                 string
	OutDir                   string
	DockerImage              string
	BinSuffix                string
	LogLevel                 string
	OmitTopology             bool
	Wirekem                  string
	Kem                      string
	Nike                     string
	UserForwardPayloadLength int
	PkiSignatureScheme       string
	NoDecoy                  bool
	NoMixDecoy               bool
	DialTimeout              int
	MaxPKIDelay              int
	PollingIntvl             int
	Sr                       uint64
	Mu                       float64
	MuMax                    uint64
	LP                       float64
	LPMax                    uint64
	LL                       float64
	LLMax                    uint64
	LD                       float64
	LDMax                    uint64
	LM                       float64
	LMMax                    uint64
	LGMax                    uint64
}

type Katzenpost struct {
	BaseDir   string
	OutDir    string
	BinSuffix string
	LogLevel  string
	LogWriter io.Writer

	WireKEMScheme      string
	PkiSignatureScheme sign.Scheme
	ReplicaNIKEScheme  nike.Scheme
	SphinxGeometry     *geo.Geometry
	PigeonholeGeometry *pigeonholeGeo.Geometry
	VotingAuthConfigs  []*vConfig.Config
	Authorities        map[[32]byte]*vConfig.Authority
	AuthIdentity       sign.PublicKey

	NodeConfigs        []*sConfig.Config
	ReplicaNodeConfigs []*rConfig.Config

	BasePort        uint16
	LastPort        uint16
	LastReplicaPort uint16
	ReplicaNodeIdx  int
	BindAddr        string
	NodeIdx         int
	GatewayIdx      int
	ServiceNodeIdx  int
	NoMixDecoy      bool
	DebugConfig     *cConfig.Debug
}

type AuthById []*vConfig.Authority

func (a AuthById) Len() int           { return len(a) }
func (a AuthById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a AuthById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type NodeById []*vConfig.Node

func (a NodeById) Len() int           { return len(a) }
func (a NodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a NodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type StorageReplicaNodeById []*vConfig.StorageReplicaNode

func (a StorageReplicaNodeById) Len() int           { return len(a) }
func (a StorageReplicaNodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a StorageReplicaNodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

func AddressesFromURLs(addrs []string) map[string][]string {
	addresses := make(map[string][]string)
	for _, addr := range addrs {
		u, err := url.Parse(addr)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case cpki.TransportTCP, cpki.TransportTCPv4, cpki.TransportTCPv6, cpki.TransportQUIC:
			if _, ok := addresses[u.Scheme]; !ok {
				addresses[u.Scheme] = make([]string, 0)
			}
			addresses[u.Scheme] = append(addresses[u.Scheme], u.String())
		default:
			continue
		}
	}
	return addresses
}

// this generates the thin client config and NOT the client2 daemon config
func (s *Katzenpost) GenClient2ThinCfg(net, addr string) error {
	log.Print("genClient2ThinCfg begin")
	os.MkdirAll(filepath.Join(s.OutDir, "client2"), 0700)
	cfg := new(thin.Config)

	cfg.SphinxGeometry = s.SphinxGeometry
	cfg.PigeonholeGeometry = s.PigeonholeGeometry
	cfg.Network = net
	cfg.Address = addr

	log.Print("before save thin config")
	err := SaveCfg(cfg, s.OutDir)
	if err != nil {
		log.Printf("save thin config failure %s", err.Error())
		return err
	}
	log.Print("after save thin config")
	log.Print("GenClient2ThinCfg end")
	return nil
}

func (s *Katzenpost) GenClient2Cfg(net, addr string) error {
	log.Print("genClient2Cfg begin")
	os.MkdirAll(filepath.Join(s.OutDir, "client2"), 0700)
	os.MkdirAll(filepath.Join(s.OutDir, "thinclient"), 0700)

	cfg := new(cConfig.Config)

	// Use TCP by default so that the CI tests pass on all platforms
	cfg.ListenNetwork = net
	cfg.ListenAddress = addr

	// Logging section.
	cfg.Logging = &cConfig.Logging{File: "", Level: DebugLogLevel}

	cfg.PKISignatureScheme = s.PkiSignatureScheme.Name()
	cfg.WireKEMScheme = s.WireKEMScheme
	cfg.SphinxGeometry = s.SphinxGeometry
	cfg.PigeonholeGeometry = s.PigeonholeGeometry

	// UpstreamProxy section
	cfg.UpstreamProxy = &cConfig.UpstreamProxy{Type: "none"}

	// VotingAuthority section
	peers := make([]*vConfig.Authority, 0)
	for _, peer := range s.Authorities {
		peers = append(peers, peer)
	}
	sort.Sort(AuthById(peers))
	cfg.VotingAuthority = &cConfig.VotingAuthority{Peers: peers}

	// Debug section
	cfg.Debug = &cConfig.Debug{DisableDecoyTraffic: s.DebugConfig.DisableDecoyTraffic}

	gateways := make([]*cConfig.Gateway, 0)
	for i := 0; i < len(s.NodeConfigs); i++ {
		if s.NodeConfigs[i].Gateway == nil {
			continue
		}

		idPubKey := CfgIdKey(s.NodeConfigs[i], s.OutDir)
		linkPubKey := CfgLinkKey(s.NodeConfigs[i], s.OutDir, cfg.WireKEMScheme)

		gateway := &cConfig.Gateway{
			PKISignatureScheme: s.PkiSignatureScheme.Name(),
			WireKEMScheme:      s.WireKEMScheme,
			Name:               s.NodeConfigs[i].Server.Identifier,
			IdentityKey:        idPubKey,
			LinkKey:            linkPubKey,
			Addresses:          s.NodeConfigs[i].Server.Addresses,
		}
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		panic("wtf 0 gateways")
	}
	cfg.PinnedGateways = &cConfig.Gateways{
		Gateways: gateways,
	}
	err := SaveCfg(cfg, s.OutDir)
	if err != nil {
		log.Printf("save client2 config failure %s", err.Error())
		return err
	}
	return nil
}

func Write(f *os.File, str string, args ...interface{}) {
	str = fmt.Sprintf(str, args...)
	_, err := f.WriteString(str)

	if err != nil {
		log.Fatal(err)
	}
}

func (s *Katzenpost) GenCourierConfig(datadir string) *courierConfig.Config {
	authorities := make([]*vConfig.Authority, 0, len(s.Authorities))
	i := 0
	for _, auth := range s.Authorities {
		authorities = append(authorities, auth)
		i += 1
	}
	sort.Sort(AuthById(authorities))
	pki := &courierConfig.PKI{
		Voting: &courierConfig.Voting{
			Authorities: authorities,
		},
	}
	const logFile = "courier.log"
	logPath := filepath.Join(datadir, logFile)
	return &courierConfig.Config{
		PKI:              pki,
		Logging:          &courierConfig.Logging{File: logPath, Level: DebugLogLevel},
		WireKEMScheme:    s.WireKEMScheme,
		PKIScheme:        s.PkiSignatureScheme.Name(),
		EnvelopeScheme:   s.ReplicaNIKEScheme.Name(),
		DataDir:          datadir,
		SphinxGeometry:   s.SphinxGeometry,
		ConnectTimeout:   config.DefaultConnectTimeout,
		HandshakeTimeout: config.DefaultHandshakeTimeout,
		ReauthInterval:   config.DefaultReauthInterval,
	}
}

func (s *Katzenpost) GenReplicaNodeConfig() error {
	log.Print("GenReplicaNodeConfig")

	cfg := new(rConfig.Config)

	cfg.Identifier = fmt.Sprintf("replica%d", s.ReplicaNodeIdx+1)
	cfg.ReplicaID = uint8(s.ReplicaNodeIdx)
	cfg.SphinxGeometry = s.SphinxGeometry
	cfg.WireKEMScheme = s.WireKEMScheme
	cfg.ReplicaNIKEScheme = s.ReplicaNIKEScheme.Name()
	cfg.PKISignatureScheme = s.PkiSignatureScheme.Name()

	cfg.Addresses = []string{fmt.Sprintf(TcpAddrFormat, s.LastReplicaPort)}
	s.LastReplicaPort++

	cfg.DataDir = filepath.Join(s.BaseDir, cfg.Identifier)
	os.MkdirAll(filepath.Join(s.OutDir, cfg.Identifier), 0700)

	// Set timeout values explicitly to use common config defaults
	cfg.ConnectTimeout = config.DefaultConnectTimeout
	cfg.HandshakeTimeout = config.DefaultHandshakeTimeout
	cfg.ReauthInterval = config.DefaultReauthInterval
	cfg.DisableDecoyTraffic = true

	authorities := make([]*vConfig.Authority, 0, len(s.Authorities))
	i := 0
	for _, auth := range s.Authorities {
		authorities = append(authorities, auth)
		i += 1
	}

	sort.Sort(AuthById(authorities))
	cfg.PKI = &rConfig.PKI{
		Voting: &rConfig.Voting{
			Authorities: authorities,
		},
	}

	cfg.Logging = new(rConfig.Logging)
	cfg.Logging.File = ServerLogFile
	//cfg.Logging.Level = s.LogLevel
	cfg.Logging.Level = DebugLogLevel

	s.ReplicaNodeConfigs = append(s.ReplicaNodeConfigs, cfg)
	_ = CfgIdKey(cfg, s.OutDir)
	_ = CfgLinkKey(cfg, s.OutDir, s.WireKEMScheme)

	s.ReplicaNodeIdx++
	return cfg.FixupAndValidate(false)
}

func (s *Katzenpost) GenNodeConfig(isGateway, isServiceNode bool, isVoting bool) error {
	n := fmt.Sprintf("mix%d", s.NodeIdx+1)
	if isGateway {
		n = fmt.Sprintf("gateway%d", s.GatewayIdx+1)
	} else if isServiceNode {
		n = fmt.Sprintf("servicenode%d", s.ServiceNodeIdx+1)
	}

	cfg := new(sConfig.Config)
	cfg.SphinxGeometry = s.SphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = s.WireKEMScheme
	cfg.Server.PKISignatureScheme = s.PkiSignatureScheme.Name()
	cfg.Server.Identifier = n
	if isGateway {
		cfg.Server.Addresses = []string{fmt.Sprintf(TcpAddrFormat, s.LastPort)}
		cfg.Server.BindAddresses = []string{fmt.Sprintf(TcpAddrFormat, s.LastPort)}
		s.LastPort += 2
	} else {
		cfg.Server.Addresses = []string{fmt.Sprintf(TcpAddrFormat, s.LastPort)}
		s.LastPort += 2
	}
	cfg.Server.DataDir = filepath.Join(s.BaseDir, n)

	os.MkdirAll(filepath.Join(s.OutDir, cfg.Server.Identifier), 0700)

	cfg.Server.IsGatewayNode = isGateway
	cfg.Server.IsServiceNode = isServiceNode
	if isGateway {
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true
	}
	if isServiceNode {
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true
	}
	// Enable Metrics endpoint
	cfg.Server.MetricsAddress = fmt.Sprintf("127.0.0.1:%d", s.LastPort)
	s.LastPort += 1

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.SendDecoyTraffic = !s.NoMixDecoy

	// PKI section.
	if isVoting {
		authorities := make([]*vConfig.Authority, 0, len(s.Authorities))
		i := 0
		for _, auth := range s.Authorities {
			authorities = append(authorities, auth)
			i += 1
		}

		sort.Sort(AuthById(authorities))
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{
				Authorities: authorities,
			},
		}
	}

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = ServerLogFile
	cfg.Logging.Level = s.LogLevel

	if isServiceNode {
		// Enable the thwack interface.
		s.ServiceNodeIdx++

		cfg.ServiceNode = &sConfig.ServiceNode{}

		serviceNodeDataDir := filepath.Join(s.OutDir, cfg.Server.Identifier)
		courierDataDir := filepath.Join(serviceNodeDataDir, CourierService)
		os.MkdirAll(courierDataDir, 0700)

		internalCourierDatadir := filepath.Join(s.BaseDir, cfg.Server.Identifier, CourierService)
		courierCfg := s.GenCourierConfig(internalCourierDatadir)

		linkPubKey := CfgLinkKey(courierCfg, courierDataDir, courierCfg.WireKEMScheme)
		linkBlob := kempem.ToPublicPEMString(linkPubKey)

		err := SaveCfg(courierCfg, serviceNodeDataDir)
		if err != nil {
			return fmt.Errorf("failed to write courier config: %s", err)
		}
		advertizeableCourierCfgPath := s.BaseDir + "/" + cfg.Server.Identifier + "/" + CourierService + "/courier.toml"
		advert := make(map[string]map[string]interface{})
		advert[CourierService] = make(map[string]interface{})
		advert[CourierService]["linkPublicKey"] = linkBlob

		// "courier" service is described in our paper, it's used to communicate
		// with the storage replicas to form the Pigeonhole storage system.
		courierPluginCfg := &sConfig.CBORPluginKaetzchen{
			Capability:        CourierService,
			Endpoint:          CourierService,
			Command:           s.BaseDir + "/courier" + s.BinSuffix,
			MaxConcurrency:    1,
			PKIAdvertizedData: advert,
			Config: map[string]interface{}{
				"c": advertizeableCourierCfgPath,
			},
		}

		proxyCfg := &sConfig.CBORPluginKaetzchen{
			Capability:     "http",
			Endpoint:       "+http",
			Command:        s.BaseDir + "/proxy_server" + s.BinSuffix,
			MaxConcurrency: 1,
			Config: map[string]interface{}{
				// allow connections to localhost:4242
				"host":      "localhost:4242",
				"log_dir":   s.BaseDir + "/" + cfg.Server.Identifier,
				"log_level": DebugLogLevel,
			},
		}

		cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{courierPluginCfg, proxyCfg}

		cfg.Debug.NumKaetzchenWorkers = 4

		echoCfg := new(sConfig.Kaetzchen)
		echoCfg.Capability = "echo"
		echoCfg.Endpoint = "+echo"
		cfg.ServiceNode.Kaetzchen = append(cfg.ServiceNode.Kaetzchen, echoCfg)
		testdestCfg := new(sConfig.Kaetzchen)
		testdestCfg.Capability = "testdest"
		testdestCfg.Endpoint = "+testdest"
		cfg.ServiceNode.Kaetzchen = append(cfg.ServiceNode.Kaetzchen, testdestCfg)

	} else if isGateway {
		s.GatewayIdx++
		cfg.Gateway = &sConfig.Gateway{}
	} else {
		s.NodeIdx++
	}
	s.NodeConfigs = append(s.NodeConfigs, cfg)
	_ = CfgIdKey(cfg, s.OutDir)
	_ = CfgLinkKey(cfg, s.OutDir, s.WireKEMScheme)
	log.Print("GenNodeConfig end")
	return cfg.FixupAndValidate()
}

func (s *Katzenpost) GenVotingAuthoritiesCfg(numAuthorities int, parameters *vConfig.Parameters, nrLayers int, wirekem string) error {

	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	s.Authorities = make(map[[32]byte]*vConfig.Authority)
	for i := 1; i <= numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.SphinxGeometry = s.SphinxGeometry
		cfg.Server = &vConfig.Server{
			WireKEMScheme:      s.WireKEMScheme,
			PKISignatureScheme: s.PkiSignatureScheme.Name(),
			Identifier:         fmt.Sprintf(AuthNodeFormat, i),
			Addresses:          []string{fmt.Sprintf(TcpAddrFormat, s.LastPort)},
			DataDir:            filepath.Join(s.BaseDir, fmt.Sprintf(AuthNodeFormat, i)),
		}
		os.MkdirAll(filepath.Join(s.OutDir, cfg.Server.Identifier), 0700)
		s.LastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    ServerLogFile,
			Level:   s.LogLevel,
		}
		cfg.Parameters = parameters
		cfg.Debug = &vConfig.Debug{
			Layers:           nrLayers,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		idKey := CfgIdKey(cfg, s.OutDir)
		linkKey := CfgLinkKey(cfg, s.OutDir, wirekem)
		authority := &vConfig.Authority{
			Identifier:         fmt.Sprintf(AuthNodeFormat, i),
			IdentityPublicKey:  idKey,
			LinkPublicKey:      linkKey,
			WireKEMScheme:      wirekem,
			PKISignatureScheme: s.PkiSignatureScheme.Name(),
			Addresses:          cfg.Server.Addresses,
		}
		s.Authorities[hash.Sum256From(idKey)] = authority
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.Authority{}
		for _, peer := range s.Authorities {
			peers = append(peers, peer)
		}
		sort.Sort(AuthById(peers))
		configs[i].Authorities = peers
	}
	s.VotingAuthConfigs = configs
	return nil
}

func (s *Katzenpost) GenAuthorizedNodes() ([]*vConfig.StorageReplicaNode, []*vConfig.Node, []*vConfig.Node, []*vConfig.Node, error) {
	replicas := []*vConfig.StorageReplicaNode{}
	for _, replicaCfg := range s.ReplicaNodeConfigs {
		node := &vConfig.StorageReplicaNode{
			Identifier:           replicaCfg.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", replicaCfg.Identifier, IdentityPublicKeyFile),
			ReplicaID:            replicaCfg.ReplicaID,
		}
		replicas = append(replicas, node)
	}

	mixes := []*vConfig.Node{}
	gateways := []*vConfig.Node{}
	serviceNodes := []*vConfig.Node{}
	for _, nodeCfg := range s.NodeConfigs {
		node := &vConfig.Node{
			Identifier:           nodeCfg.Server.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, IdentityPublicKeyFile),
		}
		if nodeCfg.Server.IsGatewayNode {
			gateways = append(gateways, node)
		} else if nodeCfg.Server.IsServiceNode {
			serviceNodes = append(serviceNodes, node)
		} else {
			mixes = append(mixes, node)
		}
	}

	sort.Sort(StorageReplicaNodeById(replicas))
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(gateways))
	sort.Sort(NodeById(serviceNodes))

	return replicas, gateways, serviceNodes, mixes, nil
}

// RunGenConfig executes the main configuration generation logic
func RunGenConfig(cfg Config) error {
	// Validate configuration
	if err := ValidateConfig(&cfg); err != nil {
		return err
	}

	// Create parameters struct for voting authorities
	parameters := &vConfig.Parameters{
		SendRatePerMinute: cfg.Sr,
		Mu:                cfg.Mu,
		MuMaxDelay:        cfg.MuMax,
		LambdaP:           cfg.LP,
		LambdaPMaxDelay:   cfg.LPMax,
		LambdaL:           cfg.LL,
		LambdaLMaxDelay:   cfg.LLMax,
		LambdaD:           cfg.LD,
		LambdaDMaxDelay:   cfg.LDMax,
		LambdaM:           cfg.LM,
		LambdaMMaxDelay:   cfg.LMMax,
		LambdaGMaxDelay:   cfg.LGMax,
	}

	// Initialize katzenpost struct
	s := InitializeKatzenpost(&cfg)

	// Setup cryptographic schemes and geometries
	if err := SetupGeometry(s, &cfg); err != nil {
		return err
	}

	// Create output directories
	os.MkdirAll(s.OutDir, 0700)
	os.MkdirAll(filepath.Join(s.OutDir, s.BaseDir), 0700)

	// Generate voting authority configurations if needed
	if cfg.Voting {
		if err := s.GenVotingAuthoritiesCfg(cfg.NrVoting, parameters, cfg.NrLayers, cfg.Wirekem); err != nil {
			return fmt.Errorf("getVotingAuthoritiesCfg failed: %s", err)
		}
	}

	// Generate all node configurations
	if err := GenerateNodes(s, &cfg); err != nil {
		return err
	}

	// Configure voting authorities and topology
	if err := ConfigureAuthorities(s, &cfg); err != nil {
		return err
	}

	// Save all configurations to disk
	if err := SaveConfigurations(s, &cfg); err != nil {
		return err
	}

	// Generate client configurations
	if err := GenerateClientConfigurations(s); err != nil {
		return err
	}

	// Generate output files (docker-compose, prometheus)
	if err := GenerateOutputFiles(s, &cfg); err != nil {
		return err
	}

	return nil
}

// ValidateConfig validates the parsed configuration and returns any errors
func ValidateConfig(cfg *Config) error {
	if cfg.Wirekem == "" {
		return fmt.Errorf("wire KEM must be set")
	}

	if cfg.Kem == "" && cfg.Nike == "" {
		return fmt.Errorf("either nike or kem must be set")
	}
	if cfg.Kem != "" && cfg.Nike != "" {
		return fmt.Errorf("nike and kem flags cannot both be set")
	}

	if kemschemes.ByName(cfg.Wirekem) == nil {
		return fmt.Errorf("invalid wire KEM scheme")
	}

	return nil
}

// InitializeKatzenpost creates and initializes a Katzenpost struct with the given configuration
func InitializeKatzenpost(cfg *Config) *Katzenpost {
	s := &Katzenpost{}

	s.WireKEMScheme = cfg.Wirekem
	s.BaseDir = cfg.BaseDir
	s.OutDir = cfg.OutDir
	s.BinSuffix = cfg.BinSuffix
	s.BasePort = uint16(cfg.BasePort)
	s.LastPort = s.BasePort + 1
	s.LastReplicaPort = s.BasePort + 3000
	s.BindAddr = cfg.BindAddr
	s.LogLevel = cfg.LogLevel
	s.DebugConfig = &cConfig.Debug{
		DisableDecoyTraffic:         cfg.NoDecoy,
		SessionDialTimeout:          cfg.DialTimeout,
		InitialMaxPKIRetrievalDelay: cfg.MaxPKIDelay,
		PollingInterval:             cfg.PollingIntvl,
	}
	s.NoMixDecoy = cfg.NoMixDecoy

	return s
}

// SetupGeometry configures the cryptographic schemes and geometries
func SetupGeometry(s *Katzenpost, cfg *Config) error {
	nrHops := cfg.NrLayers + 2

	if cfg.Nike != "" {
		nikeScheme := schemes.ByName(cfg.Nike)
		if nikeScheme == nil {
			return fmt.Errorf("failed to resolve nike scheme %s", cfg.Nike)
		}
		s.SphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.Kem != "" {
		kemScheme := kemschemes.ByName(cfg.Kem)
		if kemScheme == nil {
			return fmt.Errorf("failed to resolve kem scheme %s", cfg.Kem)
		}
		s.SphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.PkiSignatureScheme != "" {
		signScheme := signSchemes.ByName(cfg.PkiSignatureScheme)
		if signScheme == nil {
			return fmt.Errorf("failed to resolve pki signature scheme %s", cfg.PkiSignatureScheme)
		}
		s.PkiSignatureScheme = signScheme
	}

	s.ReplicaNIKEScheme = replicaCommon.NikeScheme

	// Generate pigeonhole geometry once for use in both client2 and thin client configs
	var err error
	s.PigeonholeGeometry, err = pigeonholeGeo.NewGeometryFromSphinx(s.SphinxGeometry, s.ReplicaNIKEScheme)
	if err != nil {
		return fmt.Errorf("failed to create pigeonhole geometry: %v", err)
	}

	return nil
}

// GenerateNodes creates all the different types of nodes (gateways, service nodes, mixes, replicas)
func GenerateNodes(s *Katzenpost, cfg *Config) error {
	// Generate the gateway configs.
	for i := 0; i < cfg.NrGateways; i++ {
		if err := s.GenNodeConfig(true, false, cfg.Voting); err != nil {
			return fmt.Errorf("failed to generate gateway config: %v", err)
		}
	}

	// Generate the service node configs.
	for i := 0; i < cfg.NrServiceNodes; i++ {
		if err := s.GenNodeConfig(false, true, cfg.Voting); err != nil {
			return fmt.Errorf("failed to generate service node config: %v", err)
		}
	}

	// Generate the mix node configs.
	for i := 0; i < cfg.NrNodes; i++ {
		if err := s.GenNodeConfig(false, false, cfg.Voting); err != nil {
			return fmt.Errorf("failed to generate mix node config: %v", err)
		}
	}

	// Pigeonhole storage replica node configs.
	for i := 0; i < cfg.NrStorageNodes; i++ {
		if err := s.GenReplicaNodeConfig(); err != nil {
			return fmt.Errorf("failed to generate storage replica node config: %v", err)
		}
	}

	return nil
}

// ConfigureAuthorities handles voting authority configuration and topology setup
func ConfigureAuthorities(s *Katzenpost, cfg *Config) error {
	if !cfg.Voting {
		return nil
	}

	replicas, gateways, serviceNodes, mixes, err := s.GenAuthorizedNodes()
	if err != nil {
		return fmt.Errorf("failed to generate authorized nodes: %v", err)
	}

	for _, vCfg := range s.VotingAuthConfigs {
		for _, k := range replicas {
			vCfg.StorageReplicas = append(vCfg.StorageReplicas, k)
		}
		vCfg.Mixes = mixes
		vCfg.GatewayNodes = gateways
		vCfg.ServiceNodes = serviceNodes

		if !cfg.OmitTopology {
			vCfg.Topology = new(vConfig.Topology)
			vCfg.Topology.Layers = make([]vConfig.Layer, 0)
			for i := 0; i < cfg.NrLayers; i++ {
				vCfg.Topology.Layers = append(vCfg.Topology.Layers, *new(vConfig.Layer))
				vCfg.Topology.Layers[i].Nodes = make([]vConfig.Node, 0)
			}
			for j := range mixes {
				layer := j % cfg.NrLayers
				vCfg.Topology.Layers[layer].Nodes = append(vCfg.Topology.Layers[layer].Nodes, *mixes[j])
			}
		}
	}

	return nil
}

// SaveConfigurations saves all generated configurations to disk
func SaveConfigurations(s *Katzenpost, cfg *Config) error {
	// Save voting authority configs
	if cfg.Voting {
		for _, vCfg := range s.VotingAuthConfigs {
			if err := SaveCfg(vCfg, cfg.OutDir); err != nil {
				return fmt.Errorf("failed to SaveCfg of authority: %v", err)
			}
		}
	}

	// Save node configs
	for _, v := range s.NodeConfigs {
		if err := SaveCfg(v, cfg.OutDir); err != nil {
			return fmt.Errorf("SaveCfg failure: %v", err)
		}
	}

	// Save replica configs
	for _, r := range s.ReplicaNodeConfigs {
		if err := SaveCfg(r, cfg.OutDir); err != nil {
			return fmt.Errorf("SaveCfg failure: %v", err)
		}
	}

	return nil
}

// GenerateClientConfigurations creates all client configuration files
func GenerateClientConfigurations(s *Katzenpost) error {
	clientDaemonNetwork := "tcp"
	clientDaemonAddress := "localhost:64331"

	err := s.GenClient2Cfg(clientDaemonNetwork, clientDaemonAddress)
	if err != nil {
		return fmt.Errorf("failed to generate client2 config: %v", err)
	}

	err = s.GenClient2ThinCfg(clientDaemonNetwork, clientDaemonAddress)
	if err != nil {
		return fmt.Errorf("failed to generate client2 thin config: %v", err)
	}

	return nil
}

// GenerateOutputFiles creates docker-compose and prometheus configuration files
func GenerateOutputFiles(s *Katzenpost, cfg *Config) error {
	err := s.GenDockerCompose(cfg.DockerImage)
	if err != nil {
		return fmt.Errorf("failed to generate docker-compose: %v", err)
	}

	err = s.GenPrometheus()
	if err != nil {
		return fmt.Errorf("failed to generate prometheus config: %v", err)
	}

	return nil
}

func Identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return Client2Identifier
	case *thin.Config:
		return Client2Identifier
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Server.Identifier
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *rConfig.Config:
		return cfg.(*rConfig.Config).Identifier
	case *courierConfig.Config:
		return CourierService
	default:
		log.Fatalf("identifier() passed unexpected type %v", cfg)
		return ""
	}
}

func TomlName(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return ClientIdentifier
	case *thin.Config:
		return "thinclient"
	case *sConfig.Config:
		return "katzenpost"
	case *rConfig.Config:
		return "replica"
	case *courierConfig.Config:
		return CourierService
	case *vConfig.Config:
		return "authority"
	default:
		log.Fatalf("tomlName() passed unexpected type")
		return ""
	}
}

func SaveCfg(cfg interface{}, outDir string) error {
	fileName := filepath.Join(outDir, Identifier(cfg), fmt.Sprintf("%s.toml", TomlName(cfg)))
	log.Printf(WritingLogFormat, fileName)
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("os.Create(%s) failed: %s", fileName, err)
	}
	defer f.Close()

	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

func CfgIdKey(cfg interface{}, outDir string) sign.PublicKey {
	var priv, public string
	var pkiSignatureScheme string
	switch cfg.(type) {
	case *rConfig.Config:
		priv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, IdentityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, IdentityPublicKeyFile)
		pkiSignatureScheme = cfg.(*rConfig.Config).PKISignatureScheme
	case *sConfig.Config:
		priv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, IdentityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, IdentityPublicKeyFile)
		pkiSignatureScheme = cfg.(*sConfig.Config).Server.PKISignatureScheme
	case *vConfig.Config:
		priv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, IdentityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, IdentityPublicKeyFile)
		pkiSignatureScheme = cfg.(*vConfig.Config).Server.PKISignatureScheme
	default:
		panic("wrong type")
	}

	scheme := signSchemes.ByName(pkiSignatureScheme)
	if scheme == nil {
		panic("invalid PKI signature scheme " + pkiSignatureScheme)
	}

	idPubKey, err := signpem.FromPublicPEMFile(public, scheme)
	if err == nil {
		return idPubKey
	}
	idPubKey, idKey, err := scheme.GenerateKey()
	log.Printf(WritingLogFormat, priv)
	signpem.PrivateKeyToFile(priv, idKey)
	log.Printf(WritingLogFormat, public)
	signpem.PublicKeyToFile(public, idPubKey)
	return idPubKey
}

func CfgLinkKey(cfg interface{}, outDir string, kemScheme string) kem.PublicKey {
	var linkpriv string
	var linkpublic string

	switch cfg.(type) {
	case *rConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, LinkPublicKeyFile)
	case *sConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, LinkPublicKeyFile)
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, LinkPublicKeyFile)
	case *courierConfig.Config:
		linkpriv = filepath.Join(outDir, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, LinkPublicKeyFile)
	default:
		panic("wrong type")
	}

	linkPubKey, linkPrivKey, err := kemschemes.ByName(kemScheme).GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	log.Printf(WritingLogFormat, linkpriv)
	err = kempem.PrivateKeyToFile(linkpriv, linkPrivKey)
	if err != nil {
		panic(err)
	}
	log.Printf(WritingLogFormat, linkpublic)
	err = kempem.PublicKeyToFile(linkpublic, linkPubKey)
	if err != nil {
		panic(err)
	}
	return linkPubKey
}

func (s *Katzenpost) GenPrometheus() error {
	dest := filepath.Join(s.OutDir, "prometheus.yml")
	log.Printf(WritingLogFormat, dest)

	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	Write(f, `
scrape_configs:
- job_name: katzenpost
  scrape_interval: 1s
  static_configs:
  - targets:
`)

	for _, cfg := range s.NodeConfigs {
		Write(f, `    - %s
`, cfg.Server.MetricsAddress)
	}
	return nil
}

func (s *Katzenpost) GenDockerCompose(dockerImage string) error {
	dest := filepath.Join(s.OutDir, "docker-compose.yml")
	log.Printf(WritingLogFormat, dest)
	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	replicas, gateways, serviceNodes, mixes, err := s.GenAuthorizedNodes()

	if err != nil {
		log.Fatal(err)
	}

	Write(f, `
services:
`)
	for _, p := range gateways {
		Write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/server%s -f %s/%s/katzenpost.toml
    network_mode: host

    depends_on:`, p.Identifier, dockerImage, s.BaseDir, s.BaseDir, s.BinSuffix, s.BaseDir, p.Identifier)
		for _, authCfg := range s.VotingAuthConfigs {
			Write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	for _, p := range serviceNodes {
		Write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/server%s -f %s/%s/katzenpost.toml
    network_mode: host

    depends_on:`, p.Identifier, dockerImage, s.BaseDir, s.BaseDir, s.BinSuffix, s.BaseDir, p.Identifier)
		for _, authCfg := range s.VotingAuthConfigs {
			Write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	for i := range mixes {
		// mixes in this form don't have their identifiers, because that isn't
		// part of the consensus. if/when that is fixed this could use that
		// identifier; instead it duplicates the definition of the name format
		// here.
		Write(f, `
  mix%d:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/server%s -f %s/mix%d/katzenpost.toml
    network_mode: host
    depends_on:`, i+1, dockerImage, s.BaseDir, s.BaseDir, s.BinSuffix, s.BaseDir, i+1)
		for _, authCfg := range s.VotingAuthConfigs {
			// is this depends_on stuff actually necessary?
			// there was a bit more of it before this function was regenerating docker-compose.yaml...
			Write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	// pigeonhole storage replicas
	for i := range replicas {
		// mixes in this form don't have their identifiers, because that isn't
		// part of the consensus. if/when that is fixed this could use that
		// identifier; instead it duplicates the definition of the name format
		// here.
		Write(f, `
  replica%d:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/replica%s -f %s/replica%d/replica.toml
    network_mode: host
    depends_on:`, i+1, dockerImage, s.BaseDir, s.BaseDir, s.BinSuffix, s.BaseDir, i+1)
		for _, authCfg := range s.VotingAuthConfigs {
			// is this depends_on stuff actually necessary?
			// there was a bit more of it before this function was regenerating docker-compose.yaml...
			Write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	for _, authCfg := range s.VotingAuthConfigs {
		Write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/dirauth%s -f %s/%s/authority.toml
    network_mode: host
`, authCfg.Server.Identifier, dockerImage, s.BaseDir, s.BaseDir, s.BinSuffix, s.BaseDir, authCfg.Server.Identifier)
	}

	Write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: --config.file="%s/prometheus.yml"
    network_mode: host
`, "metrics", "docker.io/prom/prometheus", s.BaseDir, s.BaseDir)

	Write(f, `
  kpclientd:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/kpclientd%s -c %s/client2/client.toml
    network_mode: host
`, dockerImage, s.BaseDir, s.BaseDir, s.BinSuffix, s.BaseDir)
	return nil
}
