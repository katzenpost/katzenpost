// voting_authority_tests.go - Katzenpost voting authority tests
// Copyright (C) 2018  David Stainton.
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

package tests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/hpcloud/tail"
	vServer "github.com/katzenpost/authority/voting/server"
	vConfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/client"
	cConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/core/utils"
	nServer "github.com/katzenpost/server"
	sConfig "github.com/katzenpost/server/config"
	"github.com/stretchr/testify/assert"
)

const (
	pingService = "loop"
	logFile     = "kimchi.log"
	basePort    = 30000
	nrNodes     = 3
	nrProviders = 1
)

var tailConfig = tail.Config{
	Poll:   true,
	Follow: true,
	Logger: tail.DiscardingLogger,
}

type serverInterface interface {
	Shutdown()
	Wait()
}

type kimchi struct {
	sync.Mutex
	sync.WaitGroup

	baseDir   string
	logWriter io.Writer

	votingAuthConfigs []*vConfig.Config

	nodeConfigs []*sConfig.Config
	lastPort    uint16
	nodeIdx     int
	providerIdx int

	servers []serverInterface
	tails   []*tail.Tail
}

func newKimchi(basePort int) *kimchi {
	//[]*sConfig.Config
	k := &kimchi{
		lastPort:          uint16(basePort + 1),
		nodeConfigs:       make([]*sConfig.Config, 0),
		votingAuthConfigs: make([]*vConfig.Config, 0),
	}
	return k
}

func (s *kimchi) initLogging() error {
	logFilePath := filepath.Join(s.baseDir, logFile)
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Log to both stdout *and* the log file.
	s.logWriter = io.MultiWriter(f, os.Stdout)
	log.SetOutput(s.logWriter)

	return nil
}

func (s *kimchi) genGoodVotingAuthoritiesCfg(numAuthorities int) error {
	parameters := &vConfig.Parameters{
		MixLambda:       1,
		MixMaxDelay:     10000,
		SendLambda:      123,
		SendShift:       12,
		SendMaxInterval: 123456,
	}
	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	peersMap := make(map[[eddsa.PublicKeySize]byte]*vConfig.AuthorityPeer)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   "DEBUG",
		}
		cfg.Parameters = parameters
		cfg.Authority = &vConfig.Authority{
			Identifier: fmt.Sprintf("authority-%v.example.org", i),
			Addresses:  []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)},
			DataDir:    filepath.Join(s.baseDir, fmt.Sprintf("authority%d", i)),
		}
		s.lastPort += 1
		privateIdentityKey, err := eddsa.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		cfg.Debug = &vConfig.Debug{
			IdentityKey:      privateIdentityKey,
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &vConfig.AuthorityPeer{
			IdentityPublicKey: cfg.Debug.IdentityKey.PublicKey(),
			LinkPublicKey:     cfg.Debug.IdentityKey.PublicKey().ToECDH(),
			Addresses:         cfg.Authority.Addresses,
		}
		peersMap[cfg.Debug.IdentityKey.PublicKey().ByteArray()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.AuthorityPeer{}
		for id, peer := range peersMap {
			if !bytes.Equal(id[:], configs[i].Debug.IdentityKey.PublicKey().Bytes()) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = append(s.votingAuthConfigs, configs...)
	return nil
}

func (s *kimchi) genBadVotingAuthoritiesCfg(numAuthorities int) error {
	parameters := &vConfig.Parameters{} // XXX all nil params means bad votes
	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	peersMap := make(map[[eddsa.PublicKeySize]byte]*vConfig.AuthorityPeer)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   "DEBUG",
		}
		cfg.Parameters = parameters
		cfg.Authority = &vConfig.Authority{
			Identifier: fmt.Sprintf("authority-%v.example.org", i),
			Addresses:  []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)},
			DataDir:    filepath.Join(s.baseDir, fmt.Sprintf("authority%d", i)),
		}
		s.lastPort += 1
		privateIdentityKey, err := eddsa.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		cfg.Debug = &vConfig.Debug{
			IdentityKey:      privateIdentityKey,
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &vConfig.AuthorityPeer{
			IdentityPublicKey: cfg.Debug.IdentityKey.PublicKey(),
			LinkPublicKey:     cfg.Debug.IdentityKey.PublicKey().ToECDH(),
			Addresses:         cfg.Authority.Addresses,
		}
		peersMap[cfg.Debug.IdentityKey.PublicKey().ByteArray()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.AuthorityPeer{}
		for id, peer := range peersMap {
			if !bytes.Equal(id[:], configs[i].Debug.IdentityKey.PublicKey().Bytes()) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = append(s.votingAuthConfigs, configs...)
	return nil
}

func (s *kimchi) genNodeConfig(isProvider bool, isVoting bool) error {
	const serverLogFile = "katzenpost.log"

	n := fmt.Sprintf("node-%d", s.nodeIdx)
	if isProvider {
		n = fmt.Sprintf("provider-%d", s.providerIdx)
	}
	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = fmt.Sprintf("%s.eXaMpLe.org", n)
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)
	cfg.Server.IsProvider = isProvider

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.NumSphinxWorkers = 1
	identity, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return err
	}
	cfg.Debug.IdentityKey = identity

	if isVoting {
		peers := []*sConfig.Peer{}
		for _, peer := range s.votingAuthConfigs {
			idKey, err := peer.Debug.IdentityKey.PublicKey().MarshalText()
			if err != nil {
				return err
			}

			linkKey, err := peer.Debug.IdentityKey.PublicKey().ToECDH().MarshalText()
			if err != nil {
				return err
			}
			p := &sConfig.Peer{
				Addresses:         peer.Authority.Addresses,
				IdentityPublicKey: string(idKey),
				LinkPublicKey:     string(linkKey),
			}
			if len(peer.Authority.Addresses) == 0 {
				panic("wtf")
			}
			peers = append(peers, p)
		}
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{
				Peers: peers,
			},
		}
	} else {
		panic("wtf")
	}

	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

		s.providerIdx++

		cfg.Provider = new(sConfig.Provider)
		cfg.Provider.AltAddresses = map[string][]string{
			"TCP":   []string{fmt.Sprintf("localhost:%d", s.lastPort)},
			"torv2": []string{"onedaythiswillbea.onion:2323"},
		}

		loopCfg := new(sConfig.Kaetzchen)
		loopCfg.Capability = "loop"
		loopCfg.Endpoint = "+loop"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, loopCfg)
	} else {
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	s.lastPort++
	err = cfg.FixupAndValidate()
	if err != nil {
		return errors.New("genNodeConfig failure on fixupandvalidate")
	}
	return nil
}

// generateWhitelist returns providers, mixes, error
func (s *kimchi) generateVotingWhitelist() ([]*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	providers := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &vConfig.Node{
				Identifier:  nodeCfg.Server.Identifier,
				IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &vConfig.Node{
			IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil
}

func (s *kimchi) runVotingAuthorities() error {
	for _, vCfg := range s.votingAuthConfigs {
		vCfg.FixupAndValidate()
		server, err := vServer.New(vCfg)
		if err != nil {
			return err
		}
		go s.logTailer(vCfg.Authority.Identifier, filepath.Join(vCfg.Authority.DataDir, vCfg.Logging.File))
		s.servers = append(s.servers, server)
	}
	return nil
}

func (s *kimchi) thwackUser(provider *sConfig.Config, user string, pubKey *ecdh.PublicKey) error {
	log.Printf("Attempting to add user: %v@%v", user, provider.Server.Identifier)

	sockFn := filepath.Join(provider.Server.DataDir, "management_sock")
	c, err := textproto.Dial("unix", sockFn)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, _, err = c.ReadResponse(int(thwack.StatusServiceReady)); err != nil {
		return err
	}

	for _, v := range []string{
		fmt.Sprintf("ADD_USER %v %v", user, pubKey),
		"QUIT",
	} {
		if err = c.PrintfLine("%v", v); err != nil {
			return err
		}
		if _, _, err = c.ReadResponse(int(thwack.StatusOk)); err != nil {
			return err
		}
	}

	return nil
}

func (s *kimchi) logTailer(prefix, path string) {
	s.Add(1)
	defer s.Done()

	l := log.New(s.logWriter, prefix+" ", 0)
	t, err := tail.TailFile(path, tailConfig)
	defer t.Cleanup()
	if err != nil {
		log.Fatalf("Failed to tail file '%v': %v", path, err)
	}

	s.Lock()
	s.tails = append(s.tails, t)
	s.Unlock()

	for line := range t.Lines {
		l.Print(line.Text)
	}
}

func (s *kimchi) makeClient(baseDir, user, provider string, privateKey *ecdh.PrivateKey, isVoting bool) *client.Client {
	dataDir := filepath.Join(baseDir, fmt.Sprintf("client_%s", user))
	err := utils.MkDataDir(dataDir)
	if err != nil {
		panic("wtf")
	}
	cfg := cConfig.Config{
		UpstreamProxy: &cConfig.UpstreamProxy{
			Type: "none",
		},
		Proxy: &cConfig.Proxy{
			DataDir: dataDir,
		},
		Logging: &cConfig.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		Debug: &cConfig.Debug{
			InitialMaxPKIRetrievalDelay: 266,
		},
		VotingAuthority: &cConfig.VotingAuthority{
			Peers: s.votingAuthConfigs[0].Authorities,
		},
		Account: &cConfig.Account{
			User:     user,
			Provider: provider,
			//ProviderKeyPin: blahblahblah,
		},
	}

	err = cfg.FixupAndValidate()
	if err != nil {
		panic("wtf")
	}

	c, err := client.New(&cfg)
	if err != nil {
		panic("wtf")
	}

	return c
}

func TestNaiveBasicVotingAuth(t *testing.T) {
	assert := assert.New(t)

	var err error
	voting := true
	votingNum := 3

	s := newKimchi(basePort)

	// TODO: Someone that cares enough can use a config file for this, but
	// this is ultimately just for testing.

	// Create the base directory and bring logging online.
	s.baseDir, err = ioutil.TempDir("", "kimchi")
	assert.NoError(err)

	err = s.initLogging()
	assert.NoError(err)

	now, elapsed, till := epochtime.Now()
	log.Printf("Epoch: %v (Elapsed: %v, Till: %v)", now, elapsed, till)
	if till < epochtime.Period-(3600*time.Second) {
		log.Printf("WARNING: Descriptor publication for the next epoch will FAIL.")
	}

	// Generate the authority configs
	err = s.genGoodVotingAuthoritiesCfg(votingNum)
	assert.NoError(err)

	// Generate the provider configs.
	for i := 0; i < nrProviders; i++ {
		if err = s.genNodeConfig(true, voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < nrNodes; i++ {
		if err = s.genNodeConfig(false, voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}

	providerWhitelist, mixWhitelist, err := s.generateVotingWhitelist()
	assert.NoError(err)

	for _, aCfg := range s.votingAuthConfigs {
		aCfg.Mixes = mixWhitelist
		aCfg.Providers = providerWhitelist
	}
	err = s.runVotingAuthorities()
	assert.NoError(err)

	// Launch all the nodes.
	for _, v := range s.nodeConfigs {
		v.FixupAndValidate()
		svr, err := nServer.New(v)
		assert.NoError(err)

		s.servers = append(s.servers, svr)
		go s.logTailer(v.Server.Identifier, filepath.Join(v.Server.DataDir, v.Logging.File))
	}

	alicePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	assert.NoError(err)

	// Initialize Alice's mailproxy.
	user := "alice"
	err = s.thwackUser(s.nodeConfigs[0], user, alicePrivateKey.PublicKey())
	assert.NoError(err)

	// Alice connects to her Provider.
	aliceClient := s.makeClient(s.baseDir, user, s.nodeConfigs[0].Server.Identifier, alicePrivateKey, true)
	_, err = aliceClient.NewSession()
	assert.NoError(err)

	//serviceDesc, err := aliceSession.GetService(pingService)
	//assert.NoError(err)
	//fmt.Println(serviceDesc.Name, serviceDesc.Provider)

	// XXX Alice does other stuff...

	// Shutdown code path.
	for _, svr := range s.servers {
		svr.Shutdown()
	}
	log.Printf("All servers halted.")

	// Wait for the log tailers to return.  This typically won't re-log the
	// shutdown sequence, but if people need the logs from that, they will
	// be in each `DataDir` as needed.
	for _, t := range s.tails {
		t.StopAtEOF()
	}
	s.Wait()
	log.Printf("Terminated.")
}

func mixnetWithGoodBadAuthorities(input BadVotingAuthTestInput) bool {
	var err error
	voting := true

	s := newKimchi(basePort)

	// TODO: Someone that cares enough can use a config file for this, but
	// this is ultimately just for testing.

	// Create the base directory and bring logging online.
	s.baseDir, err = ioutil.TempDir("", "kimchi")
	if err != nil {
		panic("wtf")
	}

	err = s.initLogging()
	if err != nil {
		panic("wtf")
	}

	now, elapsed, till := epochtime.Now()
	log.Printf("Epoch: %v (Elapsed: %v, Till: %v)", now, elapsed, till)
	if till < epochtime.Period-(3600*time.Second) {
		log.Printf("WARNING: Descriptor publication for the next epoch will FAIL.")
	}

	// Generate the authority configs
	err = s.genGoodVotingAuthoritiesCfg(input.Good)
	if err != nil {
		panic("wtf")
	}
	err = s.genBadVotingAuthoritiesCfg(input.Bad)
	if err != nil {
		panic("wtf")
	}

	// Generate the provider configs.
	for i := 0; i < nrProviders; i++ {
		if err = s.genNodeConfig(true, voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < nrNodes; i++ {
		if err = s.genNodeConfig(false, voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}

	providerWhitelist, mixWhitelist, err := s.generateVotingWhitelist()
	if err != nil {
		panic("wtf")
	}

	for _, aCfg := range s.votingAuthConfigs {
		aCfg.Mixes = mixWhitelist
		aCfg.Providers = providerWhitelist
	}
	err = s.runVotingAuthorities()
	if err != nil {
		panic("wtf")
	}

	// Launch all the nodes.
	for _, v := range s.nodeConfigs {
		v.FixupAndValidate()
		svr, err := nServer.New(v)
		if err != nil {
			panic("wtf")
		}

		s.servers = append(s.servers, svr)
		go s.logTailer(v.Server.Identifier, filepath.Join(v.Server.DataDir, v.Logging.File))
	}

	alicePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		panic("wtf")
	}

	// Initialize Alice's mailproxy.
	user := "alice"
	err = s.thwackUser(s.nodeConfigs[0], user, alicePrivateKey.PublicKey())
	if err != nil {
		panic("wtf")
	}

	// Alice connects to her Provider.
	aliceClient := s.makeClient(s.baseDir, user, s.nodeConfigs[0].Server.Identifier, alicePrivateKey, true)
	_, err = aliceClient.NewSession()
	if err != nil {
		return true
	}

	// Shutdown code path.
	for _, svr := range s.servers {
		svr.Shutdown()
	}
	log.Printf("All servers halted.")

	// Wait for the log tailers to return.  This typically won't re-log the
	// shutdown sequence, but if people need the logs from that, they will
	// be in each `DataDir` as needed.
	for _, t := range s.tails {
		t.StopAtEOF()
	}
	s.Wait()
	log.Printf("Terminated.")
	return false
}

type BadVotingAuthTestInput struct {
	Good int
	Bad  int
}

func (b BadVotingAuthTestInput) Generate(r *mrand.Rand, size int) reflect.Value {
	fmt.Println("Generate")
	i := BadVotingAuthTestInput{}
	for {
		max := 5 // XXX
		i.Good = mrand.Intn(max)
		i.Bad = mrand.Intn(max)
		if !thresholdProperty(i) {
			fmt.Printf("testing with: good %d/bad %d\n", i.Good, i.Bad)
			break
		}
	}
	return reflect.ValueOf(i)
}

func thresholdProperty(input BadVotingAuthTestInput) bool {
	nodes := input.Good + input.Bad
	if input.Good >= nodes/2+1 {
		return true
	}
	return false
}

func testTimeoutVotingThreshold(timeout time.Duration) func(BadVotingAuthTestInput) bool {
	fmt.Println("testTimeoutVotingThreshold")
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	ch := make(chan bool, 0)
	return func(input BadVotingAuthTestInput) bool {
		go func() {
			ret := mixnetWithGoodBadAuthorities(input)
			ch <- ret
		}()
		select {
		case ret := <-ch:
			return ret
		case <-ctx.Done():
			fmt.Println(ctx.Err()) // prints "context deadline exceeded"
			return true
		}
	}
}

// TestVotingThresholdProperty tests that consensus is not reached
// when there are not a threshold number of good authorities.
func TestVotingThresholdProperty(t *testing.T) {
	cfg := quick.Config{
		MaxCount: 10, // XXX how many tests?
	}
	if err := quick.Check(testTimeoutVotingThreshold(time.Hour*time.Duration(2)), &cfg); err != nil {
		t.Error(err)
	}
}
