// genconfig.go - Katzenpost self contained test network.
// Copyright (C) 2022  Yawning Angel, David Stainton, Masala
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

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

const (
	basePort      = 30000
	bindAddr      = "127.0.0.1"
	nrLayers      = 3
	nrNodes       = 6
	nrProviders   = 2
	nrAuthorities = 3
)

type katzenpost struct {
	baseDir   string
	outDir    string
	binSuffix string
	logLevel  string
	logWriter io.Writer

	wireKEMScheme     string
	sphinxGeometry    *geo.Geometry
	votingAuthConfigs []*vConfig.Config
	authorities       map[[32]byte]*vConfig.Authority
	authIdentity      sign.PublicKey

	nodeConfigs []*sConfig.Config
	basePort    uint16
	lastPort    uint16
	bindAddr    string
	nodeIdx     int
	clientIdx   int
	providerIdx int
	hasPanda    bool
}

type AuthById []*vConfig.Authority

func (a AuthById) Len() int           { return len(a) }
func (a AuthById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a AuthById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type NodeById []*vConfig.Node

func (a NodeById) Len() int           { return len(a) }
func (a NodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a NodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

func (s *katzenpost) genClientCfg() error {
	os.Mkdir(filepath.Join(s.outDir, "client"), 0700)
	cfg := new(cConfig.Config)

	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.SphinxGeometry = s.sphinxGeometry

	s.clientIdx++

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
	cfg.Debug = &cConfig.Debug{DisableDecoyTraffic: false}
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

func (s *katzenpost) genNodeConfig(isProvider bool, isVoting bool) error {
	const serverLogFile = "katzenpost.log"

	n := fmt.Sprintf("mix%d", s.nodeIdx+1)
	if isProvider {
		n = fmt.Sprintf("provider%d", s.providerIdx+1)
	}
	cfg := new(sConfig.Config)

	cfg.SphinxGeometry = s.sphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = s.wireKEMScheme
	cfg.Server.Identifier = n
	cfg.Server.Addresses = []string{fmt.Sprintf("%s:%d", s.bindAddr, s.lastPort)}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)
	os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
	cfg.Server.IsProvider = isProvider
	if isProvider {
		cfg.Server.AltAddresses = map[string][]string{
			"TCP": []string{fmt.Sprintf("localhost:%d", s.lastPort)},
		}
	}
	// Enable Metrics endpoint
	s.lastPort += 1
	cfg.Server.MetricsAddress = fmt.Sprintf("127.0.0.1:%d", s.lastPort)

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.SendDecoyTraffic = true

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

	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

		s.providerIdx++

		cfg.Provider = new(sConfig.Provider)
		// configure an entry provider or a spool storage provider
		if s.providerIdx%2 == 0 {
			cfg.Provider.TrustOnFirstUse = true
			cfg.Provider.EnableEphemeralClients = true
		} else {
			spoolCfg := &sConfig.CBORPluginKaetzchen{
				Capability:     "spool",
				Endpoint:       "+spool",
				Command:        s.baseDir + "/memspool" + s.binSuffix,
				MaxConcurrency: 1,
				Config: map[string]interface{}{
					"data_store": s.baseDir + "/" + cfg.Server.Identifier + "/memspool.storage",
					"log_dir":    s.baseDir + "/" + cfg.Server.Identifier,
				},
			}
			cfg.Provider.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{spoolCfg}
			if !s.hasPanda {
				pandaCfg := &sConfig.CBORPluginKaetzchen{
					Capability:     "panda",
					Endpoint:       "+panda",
					Command:        s.baseDir + "/panda_server" + s.binSuffix,
					MaxConcurrency: 1,
					Config: map[string]interface{}{
						"fileStore": s.baseDir + "/" + cfg.Server.Identifier + "/panda.storage",
						"log_dir":   s.baseDir + "/" + cfg.Server.Identifier,
						"log_level": s.logLevel,
					},
				}
				cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, pandaCfg)
				s.hasPanda = true
			}
		}

		echoCfg := new(sConfig.Kaetzchen)
		echoCfg.Capability = "echo"
		echoCfg.Endpoint = "+echo"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, echoCfg)

		/*
			keysvrCfg := new(sConfig.Kaetzchen)
			keysvrCfg.Capability = "keyserver"
			keysvrCfg.Endpoint = "+keyserver"
			cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, keysvrCfg)

				if s.providerIdx == 1 {
					cfg.Debug.NumProviderWorkers = 10
					cfg.Provider.SQLDB = new(sConfig.SQLDB)
					cfg.Provider.SQLDB.Backend = "pgx"
					cfg.Provider.SQLDB.DataSourceName = "host=localhost port=5432 database=katzenpost sslmode=disable"
					cfg.Provider.UserDB = new(sConfig.UserDB)
					cfg.Provider.UserDB.Backend = sConfig.BackendSQL

					cfg.Provider.SpoolDB = new(sConfig.SpoolDB)
					cfg.Provider.SpoolDB.Backend = sConfig.BackendSQL
				}
		*/
	} else {
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	s.lastPort++
	_ = cfgIdKey(cfg, s.outDir)
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
			WireKEMScheme: s.wireKEMScheme,
			Identifier:    fmt.Sprintf("auth%d", i),
			Addresses:     []string{fmt.Sprintf("%s:%d", s.bindAddr, s.lastPort)},
			DataDir:       filepath.Join(s.baseDir, fmt.Sprintf("auth%d", i)),
		}
		os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
		s.lastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
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
			Identifier:        fmt.Sprintf("auth%d", i),
			IdentityPublicKey: idKey,
			LinkPublicKey:     linkKey,
			WireKEMScheme:     wirekem,
			Addresses:         cfg.Server.Addresses,
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

func (s *katzenpost) genAuthorizedNodes() ([]*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	providers := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		node := &vConfig.Node{
			Identifier:           nodeCfg.Server.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, "identity.public.pem"),
		}
		if nodeCfg.Server.IsProvider {
			providers = append(providers, node)
		} else {
			mixes = append(mixes, node)
		}
	}
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(providers))

	return providers, mixes, nil
}

func main() {
	var err error
	nrLayers := flag.Int("L", nrLayers, "Number of layers.")
	nrNodes := flag.Int("n", nrNodes, "Number of mixes.")
	nrProviders := flag.Int("p", nrProviders, "Number of providers.")
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
	s.bindAddr = *bindAddr
	s.logLevel = *logLevel

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

	os.Mkdir(s.outDir, 0700)
	os.Mkdir(filepath.Join(s.outDir, s.baseDir), 0700)

	if *voting {
		// Generate the voting authority configurations
		err := s.genVotingAuthoritiesCfg(*nrVoting, parameters, *nrLayers, *wirekem)
		if err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	}

	// Generate the provider configs.
	for i := 0; i < *nrProviders; i++ {
		if err = s.genNodeConfig(true, *voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < *nrNodes; i++ {
		if err = s.genNodeConfig(false, *voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}
	// Generate the authority config
	if *voting {
		providers, mixes, err := s.genAuthorizedNodes()
		if err != nil {
			panic(err)
		}
		for _, vCfg := range s.votingAuthConfigs {
			vCfg.Mixes = mixes
			vCfg.Providers = providers
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
			log.Fatalf("%s", err)
		}
	}

	err = s.genClientCfg()
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
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Server.Identifier
	default:
		log.Fatalf("identifier() passed unexpected type")
		return ""
	}
}

func toml_name(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return "client"
	case *sConfig.Config:
		return "katzenpost"
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
		return err
	}
	defer f.Close()

	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

func cfgIdKey(cfg interface{}, outDir string) sign.PublicKey {
	var priv, public string
	switch cfg.(type) {
	case *sConfig.Config:
		priv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "identity.public.pem")
	case *vConfig.Config:
		priv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "identity.public.pem")
	default:
		panic("wrong type")
	}

	idPubKey, err := signpem.FromPublicPEMFile(public, cert.Scheme)
	if err == nil {
		return idPubKey
	}
	idPubKey, idKey, err := cert.Scheme.GenerateKey()
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
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.public.pem")
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

	providers, mixes, err := s.genAuthorizedNodes()

	if err != nil {
		log.Fatal(err)
	}

	write(f, `version: "2"

services:
`)
	for _, p := range providers {
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
	for _, authCfg := range s.votingAuthConfigs {
		write(f, `
  %s:
    restart: "no"
    image: %s
    volumes:
      - ./:%s
    command: %s/voting%s -f %s/%s/authority.toml
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

	return nil
}
