package genconfig

import (
	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig2 "github.com/katzenpost/katzenpost/client2/config"
	"log"
	"os"
	"path/filepath"
	"sort"
)

func (s *Katzenpost) GenClient2Cfg() error {
	log.Print("genClient2Cfg begin")
	os.Mkdir(filepath.Join(s.OutDir, "client2"), 0700)
	cfg := new(cConfig2.Config)

	//cfg.ListenNetwork = "unixpacket"
	//cfg.ListenAddress = "@katzenpost"

	cfg.ListenNetwork = "tcp"
	cfg.ListenAddress = "localhost:64331"

	cfg.PKISignatureScheme = s.PKISignatureScheme.Name()
	cfg.WireKEMScheme = s.WireKEMScheme
	cfg.SphinxGeometry = s.SphinxGeometry

	// Logging section.
	cfg.Logging = &cConfig2.Logging{File: "", Level: "DEBUG"}

	// UpstreamProxy section
	cfg.UpstreamProxy = &cConfig2.UpstreamProxy{Type: "none"}

	// VotingAuthority section

	peers := make([]*vConfig.Authority, 0)
	for _, peer := range s.Authorities {
		peers = append(peers, peer)
	}

	sort.Sort(AuthById(peers))

	cfg.VotingAuthority = &cConfig2.VotingAuthority{Peers: peers}

	// Debug section
	cfg.Debug = &cConfig2.Debug{DisableDecoyTraffic: s.DebugConfig.DisableDecoyTraffic}

	log.Print("before gathering providers")
	gateways := make([]*cConfig2.Gateway, 0)
	for i := 0; i < len(s.NodeConfigs); i++ {
		if s.NodeConfigs[i].Gateway == nil {
			continue
		}

		idPubKey := cfgIdKey(s.NodeConfigs[i], s.OutDir)
		linkPubKey := cfgLinkKey(s.NodeConfigs[i], s.OutDir, cfg.WireKEMScheme)

		gateway := &cConfig2.Gateway{
			PKISignatureScheme: s.PKISignatureScheme.Name(),
			WireKEMScheme:      s.WireKEMScheme,
			Name:               s.NodeConfigs[i].Server.Identifier,
			IdentityKey:        idPubKey,
			LinkKey:            linkPubKey,
			Addresses:          s.NodeConfigs[i].Server.Addresses,
		}
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		panic("wtf 0 providers")
	}
	log.Print("after gathering providers")
	cfg.PinnedGateways = &cConfig2.Gateways{
		Gateways: gateways,
	}

	log.Print("before save config")
	err := saveCfg(cfg, s.OutDir)
	if err != nil {
		log.Printf("save config failure %s", err.Error())
		return err
	}
	log.Print("after save config")
	log.Print("genClient2Cfg end")
	return nil
}
