package genconfig

import (
	"fmt"
	"github.com/katzenpost/hpqc/hash"
	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"os"
	"path/filepath"
	"sort"
)

func (s *Katzenpost) GenVotingAuthoritiesCfg(numAuthorities int, parameters *vConfig.Parameters, nrLayers int, wirekem string) error {

	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	s.Authorities = make(map[[32]byte]*vConfig.Authority)
	for i := 1; i <= numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.SphinxGeometry = s.SphinxGeometry
		cfg.Server = &vConfig.Server{
			WireKEMScheme:      s.WireKEMScheme,
			PKISignatureScheme: s.PKISignatureScheme.Name(),
			Identifier:         fmt.Sprintf("auth%d", i),
			Addresses:          []string{fmt.Sprintf("http://127.0.0.1:%d", s.LastPort)},
			DataDir:            filepath.Join(s.BaseDir, fmt.Sprintf("auth%d", i)),
		}
		os.Mkdir(filepath.Join(s.OutDir, cfg.Server.Identifier), 0700)
		s.LastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   s.LogLevel,
		}
		cfg.Parameters = parameters
		cfg.Debug = &vConfig.Debug{
			Layers:           nrLayers,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		idKey := cfgIdKey(cfg, s.OutDir)
		linkKey := cfgLinkKey(cfg, s.OutDir, wirekem)
		authority := &vConfig.Authority{
			Identifier:         fmt.Sprintf("auth%d", i),
			IdentityPublicKey:  idKey,
			LinkPublicKey:      linkKey,
			WireKEMScheme:      wirekem,
			PKISignatureScheme: s.PKISignatureScheme.Name(),
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

func (s *Katzenpost) GenAuthorizedNodes() ([]*vConfig.Node, []*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	gateways := []*vConfig.Node{}
	serviceNodes := []*vConfig.Node{}
	for _, nodeCfg := range s.NodeConfigs {
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
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(gateways))
	sort.Sort(NodeById(serviceNodes))

	return gateways, serviceNodes, mixes, nil
}
