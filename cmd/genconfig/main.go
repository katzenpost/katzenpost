// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

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
	cConfig "github.com/katzenpost/katzenpost/client/config"
	cConfig2 "github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/common"
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
	basePort               = 30000
	bindAddr               = "127.0.0.1"
	nrLayers               = 3
	nrNodes                = 6
	nrGateways             = 1
	nrServiceNodes         = 1
	nrStorageNodes         = 5
	nrAuthorities          = 3
	serverLogFile          = "katzenpost.log"
	tcpAddrFormat          = "tcp://127.0.0.1:%d"
	identityPublicKeyFile  = "identity.public.pem"
	identityPrivateKeyFile = "identity.private.pem"
	linkPublicKeyFile      = "link.public.pem"
	linkPrivateKeyFile     = "link.private.pem"
	courierService         = "courier"
	clientIdentifier       = "client"
	client2Identifier      = "client2"
	debugLogLevel          = "DEBUG"
	authNodeFormat         = "auth%d"
	writingLogFormat       = "writing %s"
)

// Config holds all the parsed command line flags
type Config struct {
	nrLayers                 int
	nrNodes                  int
	nrGateways               int
	nrServiceNodes           int
	nrStorageNodes           int
	voting                   bool
	nrVoting                 int
	baseDir                  string
	basePort                 int
	bindAddr                 string
	outDir                   string
	dockerImage              string
	binSuffix                string
	logLevel                 string
	omitTopology             bool
	wirekem                  string
	kem                      string
	nike                     string
	UserForwardPayloadLength int
	pkiSignatureScheme       string
	noDecoy                  bool
	noMixDecoy               bool
	dialTimeout              int
	maxPKIDelay              int
	pollingIntvl             int
	sr                       uint64
	mu                       float64
	muMax                    uint64
	lP                       float64
	lPMax                    uint64
	lL                       float64
	lLMax                    uint64
	lD                       float64
	lDMax                    uint64
	lM                       float64
	lMMax                    uint64
	lGMax                    uint64
}

type katzenpost struct {
	baseDir   string
	outDir    string
	binSuffix string
	logLevel  string
	logWriter io.Writer

	wireKEMScheme      string
	pkiSignatureScheme sign.Scheme
	replicaNIKEScheme  nike.Scheme
	sphinxGeometry     *geo.Geometry
	pigeonholeGeometry *pigeonholeGeo.Geometry
	votingAuthConfigs  []*vConfig.Config
	authorities        map[[32]byte]*vConfig.Authority
	authIdentity       sign.PublicKey

	nodeConfigs        []*sConfig.Config
	replicaNodeConfigs []*rConfig.Config

	basePort        uint16
	lastPort        uint16
	lastReplicaPort uint16
	replicaNodeIdx  int
	bindAddr        string
	nodeIdx         int
	gatewayIdx      int
	serviceNodeIdx  int
	noMixDecoy      bool
	debugConfig     *cConfig.Debug
}

type AuthById []*vConfig.Authority

func (a AuthById) Len() int           { return len(a) }
func (a AuthById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a AuthById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type NodeById []*vConfig.Node

func (a NodeById) Len() int           { return len(a) }
func (a NodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a NodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

func addressesFromURLs(addrs []string) map[string][]string {
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
func (s *katzenpost) genClient2ThinCfg(net, addr string) error {
	log.Print("genClient2ThinCfg begin")
	os.MkdirAll(filepath.Join(s.outDir, "client2"), 0700)
	cfg := new(thin.Config)

	cfg.SphinxGeometry = s.sphinxGeometry
	cfg.PigeonholeGeometry = s.pigeonholeGeometry
	cfg.Network = net
	cfg.Address = addr

	log.Print("before save thin config")
	err := saveCfg(cfg, s.outDir)
	if err != nil {
		log.Printf("save thin config failure %s", err.Error())
		return err
	}
	log.Print("after save thin config")
	log.Print("genClient2ThinCfg end")
	return nil
}

func (s *katzenpost) genClient2Cfg(net, addr string) error {
	log.Print("genClient2Cfg begin")
	os.MkdirAll(filepath.Join(s.outDir, "client2"), 0700)
	os.MkdirAll(filepath.Join(s.outDir, "thinclient"), 0700)

	cfg := new(cConfig2.Config)

	// Use TCP by default so that the CI tests pass on all platforms
	cfg.ListenNetwork = net
	cfg.ListenAddress = addr

	// Logging section.
	cfg.Logging = &cConfig2.Logging{File: "", Level: debugLogLevel}

	cfg.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.SphinxGeometry = s.sphinxGeometry
	cfg.PigeonholeGeometry = s.pigeonholeGeometry

	// UpstreamProxy section
	cfg.UpstreamProxy = &cConfig2.UpstreamProxy{Type: "none"}

	// VotingAuthority section
	peers := make([]*vConfig.Authority, 0)
	for _, peer := range s.authorities {
		peers = append(peers, peer)
	}
	sort.Sort(AuthById(peers))
	cfg.VotingAuthority = &cConfig2.VotingAuthority{Peers: peers}

	// Debug section
	cfg.Debug = &cConfig2.Debug{DisableDecoyTraffic: s.debugConfig.DisableDecoyTraffic}

	gateways := make([]*cConfig2.Gateway, 0)
	for i := 0; i < len(s.nodeConfigs); i++ {
		if s.nodeConfigs[i].Gateway == nil {
			continue
		}

		idPubKey := cfgIdKey(s.nodeConfigs[i], s.outDir)
		linkPubKey := cfgLinkKey(s.nodeConfigs[i], s.outDir, cfg.WireKEMScheme)

		gateway := &cConfig2.Gateway{
			PKISignatureScheme: s.pkiSignatureScheme.Name(),
			WireKEMScheme:      s.wireKEMScheme,
			Name:               s.nodeConfigs[i].Server.Identifier,
			IdentityKey:        idPubKey,
			LinkKey:            linkPubKey,
			Addresses:          s.nodeConfigs[i].Server.Addresses,
		}
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		panic("wtf 0 gateways")
	}
	cfg.PinnedGateways = &cConfig2.Gateways{
		Gateways: gateways,
	}
	err := saveCfg(cfg, s.outDir)
	if err != nil {
		log.Printf("save client2 config failure %s", err.Error())
		return err
	}
	return nil
}

func (s *katzenpost) genClientCfg() error {
	os.MkdirAll(filepath.Join(s.outDir, "client"), 0700)
	cfg := new(cConfig.Config)

	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.SphinxGeometry = s.sphinxGeometry

	// Logging section.
	cfg.Logging = &cConfig.Logging{File: "", Level: s.logLevel}

	// UpstreamProxy section
	cfg.UpstreamProxy = &cConfig.UpstreamProxy{Type: "none"}

	// VotingAuthority section

	peers := make([]*vConfig.Authority, 0)
	for _, peer := range s.authorities {
		peers = append(peers, peer)
	}

	sort.Sort(AuthById(peers))

	cfg.VotingAuthority = &cConfig.VotingAuthority{Peers: peers}

	// Debug section
	cfg.Debug = s.debugConfig
	err := saveCfg(cfg, s.outDir)
	if err != nil {
		return err
	}
	return nil
}

func write(f *os.File, str string, args ...interface{}) {
	str = fmt.Sprintf(str, args...)
	_, err := f.WriteString(str)

	if err != nil {
		log.Fatal(err)
	}
}

func (s *katzenpost) genCourierConfig(datadir string) *courierConfig.Config {
	authorities := make([]*vConfig.Authority, 0, len(s.authorities))
	i := 0
	for _, auth := range s.authorities {
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
		Logging:          &courierConfig.Logging{File: logPath, Level: debugLogLevel},
		WireKEMScheme:    s.wireKEMScheme,
		PKIScheme:        s.pkiSignatureScheme.Name(),
		EnvelopeScheme:   s.replicaNIKEScheme.Name(),
		DataDir:          datadir,
		SphinxGeometry:   s.sphinxGeometry,
		ConnectTimeout:   config.DefaultConnectTimeout,
		HandshakeTimeout: config.DefaultHandshakeTimeout,
		ReauthInterval:   config.DefaultReauthInterval,
	}
}

func (s *katzenpost) genReplicaNodeConfig() error {
	log.Print("genReplicaNodeConfig")

	cfg := new(rConfig.Config)

	cfg.Identifier = fmt.Sprintf("replica%d", s.replicaNodeIdx+1)
	cfg.SphinxGeometry = s.sphinxGeometry
	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.ReplicaNIKEScheme = s.replicaNIKEScheme.Name()
	cfg.PKISignatureScheme = s.pkiSignatureScheme.Name()

	cfg.Addresses = []string{fmt.Sprintf(tcpAddrFormat, s.lastReplicaPort)}
	s.lastReplicaPort++

	cfg.DataDir = filepath.Join(s.baseDir, cfg.Identifier)
	os.MkdirAll(filepath.Join(s.outDir, cfg.Identifier), 0700)

	authorities := make([]*vConfig.Authority, 0, len(s.authorities))
	i := 0
	for _, auth := range s.authorities {
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
	cfg.Logging.File = serverLogFile
	//cfg.Logging.Level = s.logLevel
	cfg.Logging.Level = debugLogLevel

	s.replicaNodeConfigs = append(s.replicaNodeConfigs, cfg)
	_ = cfgIdKey(cfg, s.outDir)
	_ = cfgLinkKey(cfg, s.outDir, s.wireKEMScheme)

	s.replicaNodeIdx++
	return cfg.FixupAndValidate(false)
}

func (s *katzenpost) genNodeConfig(isGateway, isServiceNode bool, isVoting bool) error {
	n := fmt.Sprintf("mix%d", s.nodeIdx+1)
	if isGateway {
		n = fmt.Sprintf("gateway%d", s.gatewayIdx+1)
	} else if isServiceNode {
		n = fmt.Sprintf("servicenode%d", s.serviceNodeIdx+1)
	}

	cfg := new(sConfig.Config)
	cfg.SphinxGeometry = s.sphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = s.wireKEMScheme
	cfg.Server.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.Server.Identifier = n
	if isGateway {
		cfg.Server.Addresses = []string{fmt.Sprintf(tcpAddrFormat, s.lastPort)}
		cfg.Server.BindAddresses = []string{fmt.Sprintf(tcpAddrFormat, s.lastPort)}
		s.lastPort += 2
	} else {
		cfg.Server.Addresses = []string{fmt.Sprintf(tcpAddrFormat, s.lastPort)}
		s.lastPort += 2
	}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)

	os.MkdirAll(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)

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
	cfg.Server.MetricsAddress = fmt.Sprintf("127.0.0.1:%d", s.lastPort)
	s.lastPort += 1

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.SendDecoyTraffic = !s.noMixDecoy

	// PKI section.
	if isVoting {
		authorities := make([]*vConfig.Authority, 0, len(s.authorities))
		i := 0
		for _, auth := range s.authorities {
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
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = s.logLevel

	if isServiceNode {
		// Enable the thwack interface.
		s.serviceNodeIdx++

		cfg.ServiceNode = &sConfig.ServiceNode{}

		serviceNodeDataDir := filepath.Join(s.outDir, cfg.Server.Identifier)
		courierDataDir := filepath.Join(serviceNodeDataDir, courierService)
		os.MkdirAll(courierDataDir, 0700)

		internalCourierDatadir := filepath.Join(s.baseDir, cfg.Server.Identifier, courierService)
		courierCfg := s.genCourierConfig(internalCourierDatadir)

		linkPubKey := cfgLinkKey(courierCfg, courierDataDir, courierCfg.WireKEMScheme)
		linkBlob := kempem.ToPublicPEMString(linkPubKey)

		err := saveCfg(courierCfg, serviceNodeDataDir)
		if err != nil {
			return fmt.Errorf("failed to write courier config: %s", err)
		}
		advertizeableCourierCfgPath := s.baseDir + "/" + cfg.Server.Identifier + "/" + courierService + "/courier.toml"
		advert := make(map[string]map[string]interface{})
		advert[courierService] = make(map[string]interface{})
		advert[courierService]["linkPublicKey"] = linkBlob

		// "courier" service is described in our paper, it's used to communicate
		// with the storage replicas to form the Pigeonhole storage system.
		courierPluginCfg := &sConfig.CBORPluginKaetzchen{
			Capability:        courierService,
			Endpoint:          courierService,
			Command:           s.baseDir + "/courier" + s.binSuffix,
			MaxConcurrency:    1,
			PKIAdvertizedData: advert,
			Config: map[string]interface{}{
				"c": advertizeableCourierCfgPath,
			},
		}

		// NOTE: "map" service is an alternative storage service which does NOT
		// have all the cool privacy properties that the protocol in our paper describes.
		mapCfg := &sConfig.CBORPluginKaetzchen{
			Capability:     "map",
			Endpoint:       "+map",
			Command:        s.baseDir + "/map" + s.binSuffix,
			MaxConcurrency: 1,
			Config: map[string]interface{}{
				"db":      s.baseDir + "/" + cfg.Server.Identifier + "/map.storage",
				"log_dir": s.baseDir + "/" + cfg.Server.Identifier,
			},
		}
		proxyCfg := &sConfig.CBORPluginKaetzchen{
			Capability:     "http",
			Endpoint:       "+http",
			Command:        s.baseDir + "/proxy_server" + s.binSuffix,
			MaxConcurrency: 1,
			Config: map[string]interface{}{
				// allow connections to localhost:4242
				"host":      "localhost:4242",
				"log_dir":   s.baseDir + "/" + cfg.Server.Identifier,
				"log_level": debugLogLevel,
			},
		}

		cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{courierPluginCfg, mapCfg, proxyCfg}

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
		s.gatewayIdx++
		cfg.Gateway = &sConfig.Gateway{}
	} else {
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	_ = cfgIdKey(cfg, s.outDir)
	_ = cfgLinkKey(cfg, s.outDir, s.wireKEMScheme)
	log.Print("genNodeConfig end")
	return cfg.FixupAndValidate()
}

func (s *katzenpost) genVotingAuthoritiesCfg(numAuthorities int, parameters *vConfig.Parameters, nrLayers int, wirekem string) error {

	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	s.authorities = make(map[[32]byte]*vConfig.Authority)
	for i := 1; i <= numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.SphinxGeometry = s.sphinxGeometry
		cfg.Server = &vConfig.Server{
			WireKEMScheme:      s.wireKEMScheme,
			PKISignatureScheme: s.pkiSignatureScheme.Name(),
			Identifier:         fmt.Sprintf(authNodeFormat, i),
			Addresses:          []string{fmt.Sprintf(tcpAddrFormat, s.lastPort)},
			DataDir:            filepath.Join(s.baseDir, fmt.Sprintf(authNodeFormat, i)),
		}
		os.MkdirAll(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
		s.lastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    serverLogFile,
			Level:   s.logLevel,
		}
		cfg.Parameters = parameters
		cfg.Debug = &vConfig.Debug{
			Layers:           nrLayers,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		idKey := cfgIdKey(cfg, s.outDir)
		linkKey := cfgLinkKey(cfg, s.outDir, wirekem)
		authority := &vConfig.Authority{
			Identifier:         fmt.Sprintf(authNodeFormat, i),
			IdentityPublicKey:  idKey,
			LinkPublicKey:      linkKey,
			WireKEMScheme:      wirekem,
			PKISignatureScheme: s.pkiSignatureScheme.Name(),
			Addresses:          cfg.Server.Addresses,
		}
		s.authorities[hash.Sum256From(idKey)] = authority
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.Authority{}
		for _, peer := range s.authorities {
			peers = append(peers, peer)
		}
		sort.Sort(AuthById(peers))
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = configs
	return nil
}

func (s *katzenpost) genAuthorizedNodes() ([]*vConfig.Node, []*vConfig.Node, []*vConfig.Node, []*vConfig.Node, error) {
	replicas := []*vConfig.Node{}
	for _, replicaCfg := range s.replicaNodeConfigs {
		node := &vConfig.Node{
			Identifier:           replicaCfg.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", replicaCfg.Identifier, identityPublicKeyFile),
		}
		replicas = append(replicas, node)
	}

	mixes := []*vConfig.Node{}
	gateways := []*vConfig.Node{}
	serviceNodes := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		node := &vConfig.Node{
			Identifier:           nodeCfg.Server.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, identityPublicKeyFile),
		}
		if nodeCfg.Server.IsGatewayNode {
			gateways = append(gateways, node)
		} else if nodeCfg.Server.IsServiceNode {
			serviceNodes = append(serviceNodes, node)
		} else {
			mixes = append(mixes, node)
		}
	}

	sort.Sort(NodeById(replicas))
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(gateways))
	sort.Sort(NodeById(serviceNodes))

	return replicas, gateways, serviceNodes, mixes, nil
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "genconfig",
		Short: "Generate Katzenpost mixnet configuration files",
		Long: `Generate comprehensive configuration files for a Katzenpost mixnet deployment.
This tool creates all necessary configuration files for directory authorities,
mix nodes, gateway nodes, service nodes, storage replicas, and client configurations.

Core functionality:
• Generates voting directory authority configurations with PKI consensus
• Creates mix node configurations for packet forwarding through the network
• Configures gateway nodes for client connections and traffic ingress/egress
• Sets up service nodes with plugins for storage, HTTP proxy, and other services
• Generates storage replica configurations for the Pigeonhole storage system
• Creates client configurations for both legacy and modern client implementations
• Produces Docker Compose files for easy deployment and testing
• Generates Prometheus monitoring configurations for network metrics

The tool supports both classical and post-quantum cryptographic schemes,
configurable network topologies, and comprehensive parameter tuning for
performance optimization and security requirements.`,
		Example: `  # Generate basic voting mixnet with default settings
  genconfig --voting --wirekem MLKEM768 --nike x25519 --baseDir /tmp/mixnet --outDir ./configs

  # Generate larger network with custom parameters
  genconfig --voting --nrVoting 5 --layers 5 --nodes 15 --gateways 3 \
    --serviceNodes 2 --storageNodes 7 --wirekem MLKEM768 --nike x25519 \
    --baseDir /opt/katzenpost --outDir ./production-configs

  # Generate test network with post-quantum KEM for Sphinx
  genconfig --voting --wirekem MLKEM768 --kem MLKEM768 \
    --baseDir /tmp/test --outDir ./test-configs --dockerImage katzenpost:latest

  # Generate network with custom timing parameters
  genconfig --voting --wirekem MLKEM768 --nike x25519 \
    --mu 0.01 --lP 0.002 --lM 0.1 --baseDir /tmp/mixnet --outDir ./configs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenConfig(cfg)
		},
	}

	// Network topology flags
	cmd.Flags().IntVarP(&cfg.nrLayers, "layers", "L", nrLayers,
		"number of mix layers in the network topology")
	cmd.Flags().IntVarP(&cfg.nrNodes, "nodes", "n", nrNodes,
		"number of mix nodes to generate")
	cmd.Flags().IntVar(&cfg.nrGateways, "gateways", nrGateways,
		"number of gateway nodes for client connections")
	cmd.Flags().IntVar(&cfg.nrServiceNodes, "serviceNodes", nrServiceNodes,
		"number of service nodes with plugins (storage, HTTP proxy, etc.)")
	cmd.Flags().IntVar(&cfg.nrStorageNodes, "storageNodes", nrStorageNodes,
		"number of storage replica nodes for Pigeonhole system")

	// Authority and voting flags
	cmd.Flags().BoolVarP(&cfg.voting, "voting", "v", false,
		"generate voting directory authority configuration")
	cmd.Flags().IntVar(&cfg.nrVoting, "nrVoting", nrAuthorities,
		"number of voting directory authorities to generate")
	cmd.Flags().BoolVarP(&cfg.omitTopology, "dynamic", "D", false,
		"use dynamic topology (omit fixed topology definition)")

	// Directory and deployment flags
	cmd.Flags().StringVarP(&cfg.baseDir, "baseDir", "b", "",
		"base directory path for runtime data and configurations")
	cmd.Flags().StringVarP(&cfg.outDir, "outDir", "o", "",
		"output directory path for generated configuration files")
	cmd.Flags().IntVarP(&cfg.basePort, "port", "P", basePort,
		"starting port number for network services")
	cmd.Flags().StringVarP(&cfg.bindAddr, "addr", "a", bindAddr,
		"IP address to bind network services to")

	// Docker and deployment flags
	cmd.Flags().StringVarP(&cfg.dockerImage, "dockerImage", "d", "katzenpost-go_mod",
		"Docker image name for docker-compose.yml generation")
	cmd.Flags().StringVarP(&cfg.binSuffix, "binSuffix", "S", "",
		"suffix for binary names in docker-compose.yml")

	// Cryptographic scheme flags
	cmd.Flags().StringVar(&cfg.wirekem, "wirekem", "",
		"KEM scheme for wire protocol (required, e.g., MLKEM768, XWING)")
	cmd.Flags().StringVar(&cfg.kem, "kem", "",
		"KEM scheme for Sphinx packet encryption (e.g., MLKEM768, FrodoKEM-640-SHAKE)")
	cmd.Flags().StringVar(&cfg.nike, "nike", "x25519",
		"NIKE scheme for Sphinx packet encryption (e.g., x25519, x448)")
	cmd.Flags().StringVar(&cfg.pkiSignatureScheme, "pkiScheme", "ed25519",
		"PKI signature scheme for authentication (e.g., ed25519, dilithium2)")

	// Sphinx and payload flags
	cmd.Flags().IntVar(&cfg.UserForwardPayloadLength, "UserForwardPayloadLength", 2000,
		"user forward payload length in bytes for Sphinx packets")

	// Traffic and timing flags
	cmd.Flags().BoolVar(&cfg.noDecoy, "noDecoy", true,
		"disable decoy traffic generation for clients")
	cmd.Flags().BoolVar(&cfg.noMixDecoy, "noMixDecoy", true,
		"disable decoy traffic generation for mix nodes")
	cmd.Flags().IntVar(&cfg.dialTimeout, "dialTimeout", 0,
		"session dial timeout in seconds (0 for default)")
	cmd.Flags().IntVar(&cfg.maxPKIDelay, "maxPKIDelay", 0,
		"initial maximum PKI retrieval delay in seconds (0 for default)")
	cmd.Flags().IntVar(&cfg.pollingIntvl, "pollingIntvl", 0,
		"PKI polling interval in seconds (0 for default)")

	// Advanced timing parameters
	cmd.Flags().Uint64Var(&cfg.sr, "sendRate", 0,
		"client send rate limit per minute (0 for unlimited)")
	cmd.Flags().Float64Var(&cfg.mu, "mu", 0.005,
		"inverse of mean per-hop delay (higher = faster)")
	cmd.Flags().Uint64Var(&cfg.muMax, "muMax", 1000,
		"maximum delay for mu parameter in milliseconds")
	cmd.Flags().Float64Var(&cfg.lP, "lambdaP", 0.001,
		"inverse of mean client send rate (higher = more frequent)")
	cmd.Flags().Uint64Var(&cfg.lPMax, "lambdaPMax", 1000,
		"maximum delay for lambdaP in milliseconds")
	cmd.Flags().Float64Var(&cfg.lL, "lambdaL", 0.0005,
		"inverse of mean loop decoy send rate")
	cmd.Flags().Uint64Var(&cfg.lLMax, "lambdaLMax", 1000,
		"maximum delay for lambdaL in milliseconds")
	cmd.Flags().Float64Var(&cfg.lD, "lambdaD", 0.0005,
		"inverse of mean drop decoy send rate")
	cmd.Flags().Uint64Var(&cfg.lDMax, "lambdaDMax", 3000,
		"maximum delay for lambdaD in milliseconds")
	cmd.Flags().Float64Var(&cfg.lM, "lambdaM", 0.2,
		"inverse of mean mix decoy send rate")
	cmd.Flags().Uint64Var(&cfg.lMMax, "lambdaMMax", 100,
		"maximum delay for lambdaM in milliseconds")
	cmd.Flags().Uint64Var(&cfg.lGMax, "lambdaGMax", 100,
		"maximum delay for gateway lambda in milliseconds")

	// Logging flags
	cmd.Flags().StringVar(&cfg.logLevel, "logLevel", debugLogLevel,
		"logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")

	// Mark required flags
	cmd.MarkFlagRequired("wirekem")
	cmd.MarkFlagRequired("baseDir")
	cmd.MarkFlagRequired("outDir")

	return cmd
}

// runGenConfig executes the main configuration generation logic
func runGenConfig(cfg Config) error {
	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return err
	}

	// Create parameters struct for voting authorities
	parameters := &vConfig.Parameters{
		SendRatePerMinute: cfg.sr,
		Mu:                cfg.mu,
		MuMaxDelay:        cfg.muMax,
		LambdaP:           cfg.lP,
		LambdaPMaxDelay:   cfg.lPMax,
		LambdaL:           cfg.lL,
		LambdaLMaxDelay:   cfg.lLMax,
		LambdaD:           cfg.lD,
		LambdaDMaxDelay:   cfg.lDMax,
		LambdaM:           cfg.lM,
		LambdaMMaxDelay:   cfg.lMMax,
		LambdaGMaxDelay:   cfg.lGMax,
	}

	// Initialize katzenpost struct
	s := initializeKatzenpost(&cfg)

	// Setup cryptographic schemes and geometries
	if err := setupGeometry(s, &cfg); err != nil {
		return err
	}

	// Create output directories
	os.MkdirAll(s.outDir, 0700)
	os.MkdirAll(filepath.Join(s.outDir, s.baseDir), 0700)

	// Generate voting authority configurations if needed
	if cfg.voting {
		if err := s.genVotingAuthoritiesCfg(cfg.nrVoting, parameters, cfg.nrLayers, cfg.wirekem); err != nil {
			return fmt.Errorf("getVotingAuthoritiesCfg failed: %s", err)
		}
	}

	// Generate all node configurations
	if err := generateNodes(s, &cfg); err != nil {
		return err
	}

	// Configure voting authorities and topology
	if err := configureAuthorities(s, &cfg); err != nil {
		return err
	}

	// Save all configurations to disk
	if err := saveConfigurations(s, &cfg); err != nil {
		return err
	}

	// Generate client configurations
	if err := generateClientConfigurations(s); err != nil {
		return err
	}

	// Generate output files (docker-compose, prometheus)
	if err := generateOutputFiles(s, &cfg); err != nil {
		return err
	}

	return nil
}

// validateConfig validates the parsed configuration and returns any errors
func validateConfig(cfg *Config) error {
	if cfg.wirekem == "" {
		return fmt.Errorf("wire KEM must be set")
	}

	if cfg.kem == "" && cfg.nike == "" {
		return fmt.Errorf("either nike or kem must be set")
	}
	if cfg.kem != "" && cfg.nike != "" {
		return fmt.Errorf("nike and kem flags cannot both be set")
	}

	if kemschemes.ByName(cfg.wirekem) == nil {
		return fmt.Errorf("invalid wire KEM scheme")
	}

	return nil
}

// initializeKatzenpost creates and initializes a katzenpost struct with the given configuration
func initializeKatzenpost(cfg *Config) *katzenpost {
	s := &katzenpost{}

	s.wireKEMScheme = cfg.wirekem
	s.baseDir = cfg.baseDir
	s.outDir = cfg.outDir
	s.binSuffix = cfg.binSuffix
	s.basePort = uint16(cfg.basePort)
	s.lastPort = s.basePort + 1
	s.lastReplicaPort = s.basePort + 3000
	s.bindAddr = cfg.bindAddr
	s.logLevel = cfg.logLevel
	s.debugConfig = &cConfig.Debug{
		DisableDecoyTraffic:         cfg.noDecoy,
		SessionDialTimeout:          cfg.dialTimeout,
		InitialMaxPKIRetrievalDelay: cfg.maxPKIDelay,
		PollingInterval:             cfg.pollingIntvl,
	}
	s.noMixDecoy = cfg.noMixDecoy

	return s
}

// setupGeometry configures the cryptographic schemes and geometries
func setupGeometry(s *katzenpost, cfg *Config) error {
	nrHops := cfg.nrLayers + 2

	if cfg.nike != "" {
		nikeScheme := schemes.ByName(cfg.nike)
		if nikeScheme == nil {
			return fmt.Errorf("failed to resolve nike scheme %s", cfg.nike)
		}
		s.sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.kem != "" {
		kemScheme := kemschemes.ByName(cfg.kem)
		if kemScheme == nil {
			return fmt.Errorf("failed to resolve kem scheme %s", cfg.kem)
		}
		s.sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.pkiSignatureScheme != "" {
		signScheme := signSchemes.ByName(cfg.pkiSignatureScheme)
		if signScheme == nil {
			return fmt.Errorf("failed to resolve pki signature scheme %s", cfg.pkiSignatureScheme)
		}
		s.pkiSignatureScheme = signScheme
	}

	s.replicaNIKEScheme = replicaCommon.NikeScheme

	// Generate pigeonhole geometry once for use in both client2 and thin client configs
	var err error
	s.pigeonholeGeometry, err = pigeonholeGeo.NewGeometryFromSphinx(s.sphinxGeometry, s.replicaNIKEScheme)
	if err != nil {
		return fmt.Errorf("failed to create pigeonhole geometry: %v", err)
	}

	return nil
}

// generateNodes creates all the different types of nodes (gateways, service nodes, mixes, replicas)
func generateNodes(s *katzenpost, cfg *Config) error {
	// Generate the gateway configs.
	for i := 0; i < cfg.nrGateways; i++ {
		if err := s.genNodeConfig(true, false, cfg.voting); err != nil {
			return fmt.Errorf("failed to generate gateway config: %v", err)
		}
	}

	// Generate the service node configs.
	for i := 0; i < cfg.nrServiceNodes; i++ {
		if err := s.genNodeConfig(false, true, cfg.voting); err != nil {
			return fmt.Errorf("failed to generate service node config: %v", err)
		}
	}

	// Generate the mix node configs.
	for i := 0; i < cfg.nrNodes; i++ {
		if err := s.genNodeConfig(false, false, cfg.voting); err != nil {
			return fmt.Errorf("failed to generate mix node config: %v", err)
		}
	}

	// Pigeonhole storage replica node configs.
	for i := 0; i < cfg.nrStorageNodes; i++ {
		if err := s.genReplicaNodeConfig(); err != nil {
			return fmt.Errorf("failed to generate storage replica node config: %v", err)
		}
	}

	return nil
}

// configureAuthorities handles voting authority configuration and topology setup
func configureAuthorities(s *katzenpost, cfg *Config) error {
	if !cfg.voting {
		return nil
	}

	replicas, gateways, serviceNodes, mixes, err := s.genAuthorizedNodes()
	if err != nil {
		return fmt.Errorf("failed to generate authorized nodes: %v", err)
	}

	for _, vCfg := range s.votingAuthConfigs {
		for _, k := range replicas {
			vCfg.StorageReplicas = append(vCfg.StorageReplicas, k)
		}
		vCfg.Mixes = mixes
		vCfg.GatewayNodes = gateways
		vCfg.ServiceNodes = serviceNodes

		if !cfg.omitTopology {
			vCfg.Topology = new(vConfig.Topology)
			vCfg.Topology.Layers = make([]vConfig.Layer, 0)
			for i := 0; i < cfg.nrLayers; i++ {
				vCfg.Topology.Layers = append(vCfg.Topology.Layers, *new(vConfig.Layer))
				vCfg.Topology.Layers[i].Nodes = make([]vConfig.Node, 0)
			}
			for j := range mixes {
				layer := j % cfg.nrLayers
				vCfg.Topology.Layers[layer].Nodes = append(vCfg.Topology.Layers[layer].Nodes, *mixes[j])
			}
		}
	}

	return nil
}

// saveConfigurations saves all generated configurations to disk
func saveConfigurations(s *katzenpost, cfg *Config) error {
	// Save voting authority configs
	if cfg.voting {
		for _, vCfg := range s.votingAuthConfigs {
			if err := saveCfg(vCfg, cfg.outDir); err != nil {
				return fmt.Errorf("failed to saveCfg of authority: %v", err)
			}
		}
	}

	// Save node configs
	for _, v := range s.nodeConfigs {
		if err := saveCfg(v, cfg.outDir); err != nil {
			return fmt.Errorf("saveCfg failure: %v", err)
		}
	}

	// Save replica configs
	for _, r := range s.replicaNodeConfigs {
		if err := saveCfg(r, cfg.outDir); err != nil {
			return fmt.Errorf("saveCfg failure: %v", err)
		}
	}

	return nil
}

// generateClientConfigurations creates all client configuration files
func generateClientConfigurations(s *katzenpost) error {
	err := s.genClientCfg()
	if err != nil {
		return fmt.Errorf("failed to generate client config: %v", err)
	}

	clientDaemonNetwork := "tcp"
	clientDaemonAddress := "localhost:64331"

	err = s.genClient2Cfg(clientDaemonNetwork, clientDaemonAddress)
	if err != nil {
		return fmt.Errorf("failed to generate client2 config: %v", err)
	}

	err = s.genClient2ThinCfg(clientDaemonNetwork, clientDaemonAddress)
	if err != nil {
		return fmt.Errorf("failed to generate client2 thin config: %v", err)
	}

	return nil
}

// generateOutputFiles creates docker-compose and prometheus configuration files
func generateOutputFiles(s *katzenpost, cfg *Config) error {
	err := s.genDockerCompose(cfg.dockerImage)
	if err != nil {
		return fmt.Errorf("failed to generate docker-compose: %v", err)
	}

	err = s.genPrometheus()
	if err != nil {
		return fmt.Errorf("failed to generate prometheus config: %v", err)
	}

	return nil
}

func main() {
	rootCmd := newRootCommand()

	// Use fang to execute the command with enhanced features and custom error handler
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
		fang.WithErrorHandler(common.ErrorHandlerWithUsage(rootCmd)),
	); err != nil {
		os.Exit(1)
	}
}

func identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return clientIdentifier
	case *cConfig2.Config:
		return client2Identifier
	case *thin.Config:
		return client2Identifier
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Server.Identifier
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *rConfig.Config:
		return cfg.(*rConfig.Config).Identifier
	case *courierConfig.Config:
		return courierService
	default:
		log.Fatalf("identifier() passed unexpected type %v", cfg)
		return ""
	}
}

func tomlName(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return clientIdentifier
	case *cConfig2.Config:
		return clientIdentifier
	case *thin.Config:
		return "thinclient"
	case *sConfig.Config:
		return "katzenpost"
	case *rConfig.Config:
		return "replica"
	case *courierConfig.Config:
		return courierService
	case *vConfig.Config:
		return "authority"
	default:
		log.Fatalf("tomlName() passed unexpected type")
		return ""
	}
}

func saveCfg(cfg interface{}, outDir string) error {
	fileName := filepath.Join(outDir, identifier(cfg), fmt.Sprintf("%s.toml", tomlName(cfg)))
	log.Printf(writingLogFormat, fileName)
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("os.Create(%s) failed: %s", fileName, err)
	}
	defer f.Close()

	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

func cfgIdKey(cfg interface{}, outDir string) sign.PublicKey {
	var priv, public string
	var pkiSignatureScheme string
	switch cfg.(type) {
	case *rConfig.Config:
		priv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, identityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, identityPublicKeyFile)
		pkiSignatureScheme = cfg.(*rConfig.Config).PKISignatureScheme
	case *sConfig.Config:
		priv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, identityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, identityPublicKeyFile)
		pkiSignatureScheme = cfg.(*sConfig.Config).Server.PKISignatureScheme
	case *vConfig.Config:
		priv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, identityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, identityPublicKeyFile)
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
	log.Printf(writingLogFormat, priv)
	signpem.PrivateKeyToFile(priv, idKey)
	log.Printf(writingLogFormat, public)
	signpem.PublicKeyToFile(public, idPubKey)
	return idPubKey
}

func cfgLinkKey(cfg interface{}, outDir string, kemScheme string) kem.PublicKey {
	var linkpriv string
	var linkpublic string

	switch cfg.(type) {
	case *rConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, linkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, linkPublicKeyFile)
	case *sConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, linkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, linkPublicKeyFile)
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, linkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, linkPublicKeyFile)
	case *courierConfig.Config:
		linkpriv = filepath.Join(outDir, linkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, linkPublicKeyFile)
	default:
		panic("wrong type")
	}

	linkPubKey, linkPrivKey, err := kemschemes.ByName(kemScheme).GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	log.Printf(writingLogFormat, linkpriv)
	err = kempem.PrivateKeyToFile(linkpriv, linkPrivKey)
	if err != nil {
		panic(err)
	}
	log.Printf(writingLogFormat, linkpublic)
	err = kempem.PublicKeyToFile(linkpublic, linkPubKey)
	if err != nil {
		panic(err)
	}
	return linkPubKey
}

func (s *katzenpost) genPrometheus() error {
	dest := filepath.Join(s.outDir, "prometheus.yml")
	log.Printf(writingLogFormat, dest)

	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	write(f, `
scrape_configs:
- job_name: katzenpost
  scrape_interval: 1s
  static_configs:
  - targets:
`)

	for _, cfg := range s.nodeConfigs {
		write(f, `    - %s
`, cfg.Server.MetricsAddress)
	}
	return nil
}

func (s *katzenpost) genDockerCompose(dockerImage string) error {
	dest := filepath.Join(s.outDir, "docker-compose.yml")
	log.Printf(writingLogFormat, dest)
	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	replicas, gateways, serviceNodes, mixes, err := s.genAuthorizedNodes()

	if err != nil {
		log.Fatal(err)
	}

	write(f, `
services:
`)
	for _, p := range gateways {
		write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/server%s -f %s/%s/katzenpost.toml
    network_mode: host

    depends_on:`, p.Identifier, dockerImage, s.baseDir, s.baseDir, s.binSuffix, s.baseDir, p.Identifier)
		for _, authCfg := range s.votingAuthConfigs {
			write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	for _, p := range serviceNodes {
		write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/server%s -f %s/%s/katzenpost.toml
    network_mode: host

    depends_on:`, p.Identifier, dockerImage, s.baseDir, s.baseDir, s.binSuffix, s.baseDir, p.Identifier)
		for _, authCfg := range s.votingAuthConfigs {
			write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	for i := range mixes {
		// mixes in this form don't have their identifiers, because that isn't
		// part of the consensus. if/when that is fixed this could use that
		// identifier; instead it duplicates the definition of the name format
		// here.
		write(f, `
  mix%d:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/server%s -f %s/mix%d/katzenpost.toml
    network_mode: host
    depends_on:`, i+1, dockerImage, s.baseDir, s.baseDir, s.binSuffix, s.baseDir, i+1)
		for _, authCfg := range s.votingAuthConfigs {
			// is this depends_on stuff actually necessary?
			// there was a bit more of it before this function was regenerating docker-compose.yaml...
			write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	// pigeonhole storage replicas
	for i := range replicas {
		// mixes in this form don't have their identifiers, because that isn't
		// part of the consensus. if/when that is fixed this could use that
		// identifier; instead it duplicates the definition of the name format
		// here.
		write(f, `
  replica%d:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/replica%s -f %s/replica%d/replica.toml
    network_mode: host
    depends_on:`, i+1, dockerImage, s.baseDir, s.baseDir, s.binSuffix, s.baseDir, i+1)
		for _, authCfg := range s.votingAuthConfigs {
			// is this depends_on stuff actually necessary?
			// there was a bit more of it before this function was regenerating docker-compose.yaml...
			write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	for _, authCfg := range s.votingAuthConfigs {
		write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/dirauth%s -f %s/%s/authority.toml
    network_mode: host
`, authCfg.Server.Identifier, dockerImage, s.baseDir, s.baseDir, s.binSuffix, s.baseDir, authCfg.Server.Identifier)
	}

	write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: --config.file="%s/prometheus.yml"
    network_mode: host
`, "metrics", "docker.io/prom/prometheus", s.baseDir, s.baseDir)

	write(f, `
  kpclientd:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/kpclientd%s -c %s/client2/client.toml
    network_mode: host
`, dockerImage, s.baseDir, s.baseDir, s.binSuffix, s.baseDir)
	return nil
}
