// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
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
	cConfig "github.com/katzenpost/katzenpost/client/config"
	cConfig2 "github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	courierConfig "github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/replica/common"
	rConfig "github.com/katzenpost/katzenpost/replica/config"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

const (
	basePort       = 30000
	bindAddr       = "127.0.0.1"
	nrLayers       = 3
	nrNodes        = 6
	nrGateways     = 1
	nrServiceNodes = 1
	nrStorageNodes = 3
	nrAuthorities  = 3
	serverLogFile  = "katzenpost.log"
)

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
	os.Mkdir(filepath.Join(s.outDir, "client2"), 0700)
	cfg := new(thin.Config)

	cfg.SphinxGeometry = s.sphinxGeometry
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
	os.Mkdir(filepath.Join(s.outDir, "client2"), 0700)
	os.Mkdir(filepath.Join(s.outDir, "thinclient"), 0700)

	cfg := new(cConfig2.Config)

	// Use TCP by default so that the CI tests pass on all platforms
	cfg.ListenNetwork = net
	cfg.ListenAddress = addr

	// Logging section.
	cfg.Logging = &cConfig2.Logging{File: "", Level: "DEBUG"}

	cfg.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.SphinxGeometry = s.sphinxGeometry

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
	os.Mkdir(filepath.Join(s.outDir, "client"), 0700)
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
		Logging:          &courierConfig.Logging{File: logPath, Level: "DEBUG"},
		WireKEMScheme:    s.wireKEMScheme,
		PKIScheme:        s.pkiSignatureScheme.Name(),
		EnvelopeScheme:   s.replicaNIKEScheme.Name(),
		DataDir:          datadir,
		SphinxGeometry:   s.sphinxGeometry,
		ConnectTimeout:   courierConfig.DefaultConnectTimeout,
		HandshakeTimeout: courierConfig.DefaultHandshakeTimeout,
		ReauthInterval:   courierConfig.DefaultReauthInterval,
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

	cfg.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastReplicaPort)}
	s.lastReplicaPort++

	cfg.DataDir = filepath.Join(s.baseDir, cfg.Identifier)
	os.Mkdir(filepath.Join(s.outDir, cfg.Identifier), 0700)

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
	cfg.Logging.Level = "DEBUG"

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
		cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort)}
		cfg.Server.BindAddresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort)}
		s.lastPort += 2
	} else {
		cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort)}
		s.lastPort += 2
	}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)

	os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)

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
		courierDataDir := filepath.Join(serviceNodeDataDir, "courier")
		os.Mkdir(courierDataDir, 0700)

		internalCourierDatadir := filepath.Join(s.baseDir, cfg.Server.Identifier, "courier")
		courierCfg := s.genCourierConfig(internalCourierDatadir)

		linkPubKey := cfgLinkKey(courierCfg, courierDataDir, courierCfg.WireKEMScheme)
		linkBlob := kempem.ToPublicPEMString(linkPubKey)

		err := saveCfg(courierCfg, serviceNodeDataDir)
		if err != nil {
			return fmt.Errorf("failed to write courier config: %s", err)
		}
		advertizeableCourierCfgPath := s.baseDir + "/" + cfg.Server.Identifier + "/courier/courier.toml"
		advert := make(map[string]map[string]interface{})
		advert["courier"] = make(map[string]interface{})
		advert["courier"]["linkPublicKey"] = linkBlob

		// "courier" service is described in our paper, it's used to communicate
		// with the storage replicas to form the Pigeonhole storage system.
		courierPluginCfg := &sConfig.CBORPluginKaetzchen{
			Capability:        "courier",
			Endpoint:          "courier",
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
				"log_level": "DEBUG",
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
			Identifier:         fmt.Sprintf("auth%d", i),
			Addresses:          []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort)},
			DataDir:            filepath.Join(s.baseDir, fmt.Sprintf("auth%d", i)),
		}
		os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
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
			Identifier:         fmt.Sprintf("auth%d", i),
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
			IdentityPublicKeyPem: filepath.Join("../", replicaCfg.Identifier, "identity.public.pem"),
		}
		replicas = append(replicas, node)
	}

	mixes := []*vConfig.Node{}
	gateways := []*vConfig.Node{}
	serviceNodes := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		node := &vConfig.Node{
			Identifier:           nodeCfg.Server.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, "identity.public.pem"),
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

func main() {
	var err error
	nrLayers := flag.Int("L", nrLayers, "Number of layers.")
	nrNodes := flag.Int("n", nrNodes, "Number of mixes.")

	nrGateways := flag.Int("gateways", nrGateways, "Number of gateway nodes.")
	nrServiceNodes := flag.Int("serviceNodes", nrServiceNodes, "Number of service nodes.")
	nrStorageNodes := flag.Int("storageNodes", nrStorageNodes, "Number of storage replica nodes.")

	voting := flag.Bool("v", false, "Generate voting configuration")
	nrVoting := flag.Int("nv", nrAuthorities, "Generate voting configuration")
	baseDir := flag.String("b", "", "Path to use as baseDir option")
	basePort := flag.Int("P", basePort, "First port number to use")
	bindAddr := flag.String("a", bindAddr, "Address to bind to")
	outDir := flag.String("o", "", "Path to write files to")
	dockerImage := flag.String("d", "katzenpost-go_mod", "Docker image for compose-compose")
	binSuffix := flag.String("S", "", "suffix for binaries in docker-compose.yml")
	logLevel := flag.String("log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	omitTopology := flag.Bool("D", false, "Dynamic topology (omit fixed topology definition)")
	wirekem := flag.String("wirekem", "", "Name of the KEM Scheme to be used with wire protocol")
	kem := flag.String("kem", "", "Name of the KEM Scheme to be used with Sphinx")
	nike := flag.String("nike", "x25519", "Name of the NIKE Scheme to be used with Sphinx")

	UserForwardPayloadLength := flag.Int("UserForwardPayloadLength", 2000, "UserForwardPayloadLength")
	pkiSignatureScheme := flag.String("pkiScheme", "ed25519", "PKI Signature Scheme to be used")
	noDecoy := flag.Bool("noDecoy", true, "Disable decoy traffic for the client")
	noMixDecoy := flag.Bool("noMixDecoy", true, "Disable decoy traffic for the mixes")
	dialTimeout := flag.Int("dialTimeout", 0, "Session dial timeout")
	maxPKIDelay := flag.Int("maxPKIDelay", 0, "Initial maximum PKI retrieval delay")
	pollingIntvl := flag.Int("pollingIntvl", 0, "Polling interval")

	sr := flag.Uint64("sr", 0, "Sendrate limit")
	mu := flag.Float64("mu", 0.005, "Inverse of mean of per hop delay.")
	muMax := flag.Uint64("muMax", 1000, "Maximum delay for Mu.")
	lP := flag.Float64("lP", 0.001, "Inverse of mean for client send rate LambdaP")
	lPMax := flag.Uint64("lPMax", 1000, "Maximum delay for LambdaP.")
	lL := flag.Float64("lL", 0.0005, "Inverse of mean of loop decoy send rate LambdaL")
	lLMax := flag.Uint64("lLMax", 1000, "Maximum delay for LambdaL")
	lD := flag.Float64("lD", 0.0005, "Inverse of mean of drop decoy send rate LambdaD")
	lDMax := flag.Uint64("lDMax", 3000, "Maximum delay for LambaD")
	lM := flag.Float64("lM", 0.2, "Inverse of mean of mix decoy send rate")
	lMMax := flag.Uint64("lMMax", 100, "Maximum delay for LambdaM")
	lGMax := flag.Uint64("lGMax", 100, "Maximum delay for LambdaM")

	flag.Parse()

	if *wirekem == "" {
		log.Fatal("wire KEM must be set")
	}

	if *kem == "" && *nike == "" {
		log.Fatal("either nike or kem must be set")
	}
	if *kem != "" && *nike != "" {
		log.Fatal("nike and kem flags cannot both be set")
	}

	parameters := &vConfig.Parameters{
		SendRatePerMinute: *sr,
		Mu:                *mu,
		MuMaxDelay:        *muMax,
		LambdaP:           *lP,
		LambdaPMaxDelay:   *lPMax,
		LambdaL:           *lL,
		LambdaLMaxDelay:   *lLMax,
		LambdaD:           *lD,
		LambdaDMaxDelay:   *lDMax,
		LambdaM:           *lM,
		LambdaMMaxDelay:   *lMMax,
		LambdaGMaxDelay:   *lGMax,
	}

	s := &katzenpost{}

	s.wireKEMScheme = *wirekem
	if kemschemes.ByName(*wirekem) == nil {
		log.Fatal("invalid wire KEM scheme")
	}

	s.baseDir = *baseDir
	s.outDir = *outDir
	s.binSuffix = *binSuffix
	s.basePort = uint16(*basePort)
	s.lastPort = s.basePort + 1
	s.lastReplicaPort = s.basePort + 3000
	s.bindAddr = *bindAddr
	s.logLevel = *logLevel
	s.debugConfig = &cConfig.Debug{
		DisableDecoyTraffic:         *noDecoy,
		SessionDialTimeout:          *dialTimeout,
		InitialMaxPKIRetrievalDelay: *maxPKIDelay,
		PollingInterval:             *pollingIntvl,
	}
	s.noMixDecoy = *noMixDecoy

	nrHops := *nrLayers + 2

	if *nike != "" {
		nikeScheme := schemes.ByName(*nike)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve nike scheme %s", *nike)
		}
		s.sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *kem != "" {
		kemScheme := kemschemes.ByName(*kem)
		if kemScheme == nil {
			log.Fatalf("failed to resolve kem scheme %s", *kem)
		}
		s.sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *pkiSignatureScheme != "" {
		signScheme := signSchemes.ByName(*pkiSignatureScheme)
		if signScheme == nil {
			log.Fatalf("failed to resolve pki signature scheme %s", *pkiSignatureScheme)
		}
		s.pkiSignatureScheme = signScheme
	}

	s.replicaNIKEScheme = common.NikeScheme

	os.Mkdir(s.outDir, 0700)
	os.Mkdir(filepath.Join(s.outDir, s.baseDir), 0700)

	if *voting {
		// Generate the voting authority configurations
		err := s.genVotingAuthoritiesCfg(*nrVoting, parameters, *nrLayers, *wirekem)
		if err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	}

	// Generate the gateway configs.
	for i := 0; i < *nrGateways; i++ {
		if err = s.genNodeConfig(true, false, *voting); err != nil {
			log.Fatalf("Failed to generate gateway config: %v", err)
		}
	}
	// Generate the service node configs.
	for i := 0; i < *nrServiceNodes; i++ {
		if err = s.genNodeConfig(false, true, *voting); err != nil {
			log.Fatalf("Failed to generate service node config: %v", err)
		}
	}

	// Generate the mix node configs.
	for i := 0; i < *nrNodes; i++ {
		if err = s.genNodeConfig(false, false, *voting); err != nil {
			log.Fatalf("Failed to generate mix node config: %v", err)
		}
	}

	// Pigeonhole storage replica node configs.
	for i := 0; i < *nrStorageNodes; i++ {
		if err = s.genReplicaNodeConfig(); err != nil {
			log.Fatalf("Failed to generate storage replica node config: %v", err)
		}
	}

	// Generate the authority config
	if *voting {
		replicas, gateways, serviceNodes, mixes, err := s.genAuthorizedNodes()
		if err != nil {
			panic(err)
		}
		for _, vCfg := range s.votingAuthConfigs {

			for _, k := range replicas {
				vCfg.StorageReplicas = append(vCfg.StorageReplicas, k)
			}
			vCfg.Mixes = mixes
			vCfg.GatewayNodes = gateways
			vCfg.ServiceNodes = serviceNodes
			if *omitTopology == false {
				vCfg.Topology = new(vConfig.Topology)
				vCfg.Topology.Layers = make([]vConfig.Layer, 0)
				for i := 0; i < *nrLayers; i++ {
					vCfg.Topology.Layers = append(vCfg.Topology.Layers, *new(vConfig.Layer))
					vCfg.Topology.Layers[i].Nodes = make([]vConfig.Node, 0)
				}
				for j := range mixes {
					layer := j % *nrLayers
					vCfg.Topology.Layers[layer].Nodes = append(vCfg.Topology.Layers[layer].Nodes, *mixes[j])
				}
			}
		}
		for _, vCfg := range s.votingAuthConfigs {
			if err := saveCfg(vCfg, *outDir); err != nil {
				log.Fatalf("Failed to saveCfg of authority with %s", err)
			}
		}
	}
	// write the mixes keys and configs to disk
	for _, v := range s.nodeConfigs {
		if err := saveCfg(v, *outDir); err != nil {
			log.Fatalf("saveCfg failure: %s", err)
		}
	}

	// replicas
	for _, r := range s.replicaNodeConfigs {
		if err := saveCfg(r, *outDir); err != nil {
			log.Fatalf("saveCfg failure: %s", err)
		}
	}

	err = s.genClientCfg()
	if err != nil {
		log.Fatalf("%s", err)
	}

	clientDaemonNetwork := "tcp"
	clientDaemonAddress := "localhost:64331"

	err = s.genClient2Cfg(clientDaemonNetwork, clientDaemonAddress)
	if err != nil {
		log.Fatalf("%s", err)
	}

	err = s.genClient2ThinCfg(clientDaemonNetwork, clientDaemonAddress)
	if err != nil {
		log.Fatalf("%s", err)
	}

	err = s.genDockerCompose(*dockerImage)
	if err != nil {
		log.Fatalf("%s", err)
	}
	err = s.genPrometheus()
	if err != nil {
		log.Fatalf("%s", err)
	}
}

func identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return "client"
	case *cConfig2.Config:
		return "client2"
	case *thin.Config:
		return "client2"
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Server.Identifier
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *rConfig.Config:
		return cfg.(*rConfig.Config).Identifier
	case *courierConfig.Config:
		return "courier"
	default:
		log.Fatalf("identifier() passed unexpected type %v", cfg)
		return ""
	}
}

func toml_name(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return "client"
	case *cConfig2.Config:
		return "client"
	case *thin.Config:
		return "thinclient"
	case *sConfig.Config:
		return "katzenpost"
	case *rConfig.Config:
		return "replica"
	case *courierConfig.Config:
		return "courier"
	case *vConfig.Config:
		return "authority"
	default:
		log.Fatalf("toml_name() passed unexpected type")
		return ""
	}
}

func saveCfg(cfg interface{}, outDir string) error {
	fileName := filepath.Join(outDir, identifier(cfg), fmt.Sprintf("%s.toml", toml_name(cfg)))
	log.Printf("writing %s", fileName)
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
		priv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, "identity.public.pem")
		pkiSignatureScheme = cfg.(*rConfig.Config).PKISignatureScheme
	case *sConfig.Config:
		priv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "identity.public.pem")
		pkiSignatureScheme = cfg.(*sConfig.Config).Server.PKISignatureScheme
	case *vConfig.Config:
		priv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "identity.public.pem")
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
	log.Printf("writing %s", priv)
	signpem.PrivateKeyToFile(priv, idKey)
	log.Printf("writing %s", public)
	signpem.PublicKeyToFile(public, idPubKey)
	return idPubKey
}

func cfgLinkKey(cfg interface{}, outDir string, kemScheme string) kem.PublicKey {
	var linkpriv string
	var linkpublic string

	switch cfg.(type) {
	case *rConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, "link.public.pem")
	case *sConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "link.public.pem")
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.public.pem")
	case *courierConfig.Config:
		linkpriv = filepath.Join(outDir, "link.private.pem")
		linkpublic = filepath.Join(outDir, "link.public.pem")
	default:
		panic("wrong type")
	}

	linkPubKey, linkPrivKey, err := kemschemes.ByName(kemScheme).GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	log.Printf("writing %s", linkpriv)
	err = kempem.PrivateKeyToFile(linkpriv, linkPrivKey)
	if err != nil {
		panic(err)
	}
	log.Printf("writing %s", linkpublic)
	err = kempem.PublicKeyToFile(linkpublic, linkPubKey)
	if err != nil {
		panic(err)
	}
	return linkPubKey
}

func (s *katzenpost) genPrometheus() error {
	dest := filepath.Join(s.outDir, "prometheus.yml")
	log.Printf("writing %s", dest)

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
	log.Printf("writing %s", dest)
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
