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
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	aConfig "github.com/katzenpost/katzenpost/authority/nonvoting/server/config"
	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/wire"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

const (
	basePort      = 30000
	nrNodes       = 6
	nrProviders   = 2
	nrAuthorities = 3
)

type katzenpost struct {
	baseDir   string
	outDir    string
	logWriter io.Writer

	authConfig        *aConfig.Config
	votingAuthConfigs []*vConfig.Config
	authorities       map[[32]byte]*vConfig.Authority
	authIdentity      sign.PublicKey

	nodeConfigs []*sConfig.Config
	lastPort    uint16
	nodeIdx     int
	clientIdx   int
	providerIdx int
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
	s.clientIdx++

	// Logging section.
	cfg.Logging = &cConfig.Logging{File: "", Level: "DEBUG"}

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
	cfg.Debug = &cConfig.Debug{DisableDecoyTraffic: true}
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

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = n
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)
	os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
	cfg.Server.IsProvider = isProvider
	if isProvider {
		cfg.Server.AltAddresses = map[string][]string{
			"TCP": []string{fmt.Sprintf("localhost:%d", s.lastPort)},
		}
	}

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// PKI section.
	if isVoting {
		authorities := make([]*vConfig.Authority, 0, len(s.votingAuthConfigs))
		for _, authCfg := range s.votingAuthConfigs {
			auth := &vConfig.Authority{
				Identifier:        authCfg.Server.Identifier,
				IdentityPublicKey: cfgIdKey(authCfg, s.outDir),
				LinkPublicKey:     cfgLinkKey(authCfg, s.outDir),
				Addresses:         authCfg.Server.Addresses,
			}
			authorities = append(authorities, auth)
		}
		sort.Sort(AuthById(authorities))
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{
				Authorities: authorities,
			},
		}
	} else {
		cfg.PKI = new(sConfig.PKI)
		cfg.PKI.Nonvoting = new(sConfig.Nonvoting)
		cfg.PKI.Nonvoting.Address = fmt.Sprintf("127.0.0.1:%d", basePort)
		cfg.PKI.Nonvoting.PublicKey = s.authIdentity
	}

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"

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
			cfg.Provider.BinaryRecipients = true
		} else {
			spoolCfg := &sConfig.CBORPluginKaetzchen{
				Capability:     "spool",
				Endpoint:       "+spool",
				Command:        "/go/bin/memspool",
				MaxConcurrency: 1,
				Config: map[string]interface{}{
					"data_store": "/conf/" + cfg.Server.Identifier + "memspool.storage",
					"log_dir":    "/conf/" + cfg.Server.Identifier,
				},
			}
			cfg.Provider.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{spoolCfg}
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

func (s *katzenpost) genAuthConfig() error {
	const authLogFile = "authority.log"

	cfg := new(aConfig.Config)

	// Server section.
	cfg.Server = new(aConfig.Server)
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", basePort)}
	cfg.Server.DataDir = filepath.Join(s.baseDir, "authority")

	// Logging section.
	cfg.Logging = new(aConfig.Logging)
	cfg.Logging.File = authLogFile
	cfg.Logging.Level = "DEBUG"

	// Mkdir
	os.Mkdir(cfg.Server.DataDir, 0700)

	// Generate keys
	priv := filepath.Join(s.outDir, "authority", "identity.private.pem")
	public := filepath.Join(s.outDir, "authority", "identity.public.pem")

	// cert.
	idKey, idPubKey := cert.Scheme.NewKeypair()
	err := pem.ToFile(priv, idKey)
	if err != nil {
		return err
	}
	err = pem.ToFile(public, idPubKey)
	if err != nil {
		return err
	}

	s.authIdentity = idPubKey
	if err != nil {
		return err
	}

	// Debug section.
	cfg.Debug = new(aConfig.Debug)

	if err := cfg.FixupAndValidate(); err != nil {
		return err
	}
	s.authConfig = cfg
	return nil
}

func (s *katzenpost) genVotingAuthoritiesCfg(numAuthorities int) error {
	parameters := &vConfig.Parameters{}
	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	s.authorities = make(map[[32]byte]*vConfig.Authority)
	for i := 1; i <= numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.Server = &vConfig.Server{
			Identifier: fmt.Sprintf("auth%d", i),
			Addresses:  []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)},
			DataDir:    filepath.Join(s.baseDir, fmt.Sprintf("auth%d", i)),
		}
		os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
		s.lastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   "DEBUG",
		}
		cfg.Parameters = parameters
		cfg.Debug = &vConfig.Debug{
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		idKey := cfgIdKey(cfg, s.outDir)
		linkKey := cfgLinkKey(cfg, s.outDir)
		authority := &vConfig.Authority{
			Identifier:        fmt.Sprintf("auth%d", i),
			IdentityPublicKey: idKey,
			LinkPublicKey:     linkKey,
			Addresses:         cfg.Server.Addresses,
		}
		s.authorities[idKey.Sum256()] = authority
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		h := cfgIdKey(configs[i], s.outDir).Sum256()
		peers := []*vConfig.Authority{}
		for id, peer := range s.authorities {
			if !bytes.Equal(id[:], h[:]) {
				peers = append(peers, peer)
			}
		}
		sort.Sort(AuthById(peers))
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = configs
	return nil
}

func (s *katzenpost) genNonVotingAuthorizedNodes() ([]*aConfig.Node, []*aConfig.Node, error) {
	mixes := []*aConfig.Node{}
	providers := []*aConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &aConfig.Node{
				Identifier:     nodeCfg.Server.Identifier,
				IdentityKeyPem: filepath.Join(s.baseDir, nodeCfg.Server.Identifier, "identity.public.pem"),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &aConfig.Node{
			IdentityKeyPem: filepath.Join(s.baseDir, nodeCfg.Server.Identifier, "identity.public.pem"),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil
}

func (s *katzenpost) genAuthorizedNodes() ([]*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	providers := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			node := &vConfig.Node{
				Identifier:           nodeCfg.Server.Identifier,
				IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, "identity.public.pem"),
			}
			providers = append(providers, node)
		} else {
			node := &vConfig.Node{
				IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, "identity.public.pem"),
			}
			mixes = append(mixes, node)
		}
	}
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(providers))

	return providers, mixes, nil
}

func main() {
	var err error
	nrNodes := flag.Int("n", nrNodes, "Number of mixes.")
	nrProviders := flag.Int("p", nrProviders, "Number of providers.")
	voting := flag.Bool("v", false, "Generate voting configuration")
	nrVoting := flag.Int("nv", nrAuthorities, "Generate voting configuration")
	baseDir := flag.String("b", "", "Path to use as baseDir option")
	outDir := flag.String("o", "", "Path to write files to")
	flag.Parse()
	s := &katzenpost{
		lastPort: basePort + 1,
	}

	s.baseDir = *baseDir
	s.outDir = *outDir

	os.Mkdir(s.outDir, 0700)
	os.Mkdir(filepath.Join(s.outDir, s.baseDir), 0700)

	if *voting {
		// Generate the voting authority configurations
		err := s.genVotingAuthoritiesCfg(*nrVoting)
		if err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	} else {
		panic("non-voting mode is not currently supported")
		if err = s.genAuthConfig(); err != nil {
			log.Fatalf("Failed to generate authority config: %v", err)
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
		for _, aCfg := range s.votingAuthConfigs {
			aCfg.Mixes = mixes
			aCfg.Providers = providers
		}
		for _, aCfg := range s.votingAuthConfigs {
			if err := saveCfg(aCfg, *outDir); err != nil {
				log.Fatalf("Failed to saveCfg of authority with %s", err)
			}
		}
	} else {
		// The node lists.
		if providers, mixes, err := s.genNonVotingAuthorizedNodes(); err == nil {
			s.authConfig.Mixes = mixes
			s.authConfig.Providers = providers
		} else {
			log.Fatalf("Failed to genNonVotingAuthorizedNodes with %s", err)
		}

		if err := saveCfg(s.authConfig, *outDir); err != nil {
			log.Fatalf("Failed to saveCfg of authority with %s", err)
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

	err = s.genDockerCompose()
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
	case *aConfig.Config:
		return "authority"
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
	case *aConfig.Config:
		return "nonvoting"
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

	idKey, idPubKey := cert.Scheme.NewKeypair()
	err := pem.FromFile(public, idPubKey)
	if err == nil {
		return idPubKey
	}
	idKey, idPubKey = cert.Scheme.NewKeypair()
	log.Printf("writing %s", priv)
	pem.ToFile(priv, idKey)
	log.Printf("writing %s", public)
	pem.ToFile(public, idPubKey)
	return idPubKey
}

func cfgLinkKey(cfg interface{}, outDir string) wire.PublicKey {
	var linkpriv string
	var linkpublic string

	switch cfg.(type) {
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.public.pem")
	default:
		panic("wrong type")
	}

	linkPrivKey, linkPubKey := wire.DefaultScheme.GenerateKeypair(rand.Reader)
	err := pem.FromFile(linkpriv, linkPrivKey)
	if err == nil {
		return linkPrivKey.PublicKey()
	}
	linkPrivKey, linkPubKey = wire.DefaultScheme.GenerateKeypair(rand.Reader)
	log.Printf("writing %s", linkpriv)
	err = pem.ToFile(linkpriv, linkPrivKey)
	if err != nil {
		panic(err)
	}
	log.Printf("writing %s", linkpublic)
	err = pem.ToFile(linkpublic, linkPubKey)
	if err != nil {
		panic(err)
	}
	return linkPubKey
}

func (s *katzenpost) genDockerCompose() error {
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
    restart: unless-stopped
    image: katzenpost/server
    volumes:
      - ./:/conf
    command: /go/bin/server -f /conf/%s/katzenpost.toml
    network_mode: host

    depends_on:`, p.Identifier, p.Identifier)
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
    restart: unless-stopped
    image: katzenpost/server
    volumes:
      - ./:/conf
    command: /go/bin/server -f /conf/mix%d/katzenpost.toml
    network_mode: host
    depends_on:`, i+1, i+1)
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
    restart: unless-stopped
    image: katzenpost/voting_authority
    volumes:
      - ./:/conf
    command: /go/bin/voting -f /conf/%s/authority.toml
    network_mode: host
`, authCfg.Server.Identifier, authCfg.Server.Identifier)
	}
	return nil
}
