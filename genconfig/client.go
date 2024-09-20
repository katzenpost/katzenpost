package genconfig

import (
	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client/config"
	"os"
	"path/filepath"
	"sort"
)

func (s *Katzenpost) GenClientCfg() error {
	os.Mkdir(filepath.Join(s.OutDir, "client"), 0700)
	cfg := new(cConfig.Config)

	cfg.RatchetNIKEScheme = s.RatchetNIKEScheme
	cfg.WireKEMScheme = s.WireKEMScheme
	cfg.PKISignatureScheme = s.PKISignatureScheme.Name()
	cfg.SphinxGeometry = s.SphinxGeometry

	s.clientIdx++

	// Logging section.
	cfg.Logging = &cConfig.Logging{File: "", Level: s.LogLevel}

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
	cfg.Debug = s.DebugConfig
	err := saveCfg(cfg, s.OutDir)
	if err != nil {
		return err
	}
	return nil
}
