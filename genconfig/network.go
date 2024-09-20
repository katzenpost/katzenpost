package genconfig

import (
	"github.com/katzenpost/hpqc/sign"
	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	sConfig "github.com/katzenpost/katzenpost/server/config"
	"os"
	"path/filepath"
)

type Katzenpost struct {
	BaseDir   string
	OutDir    string
	BinSuffix string
	LogLevel  string

	Parameters         *vConfig.Parameters
	RatchetNIKEScheme  string
	WireKEMScheme      string
	PKISignatureScheme sign.Scheme
	SphinxGeometry     *geo.Geometry
	VotingAuthConfigs  []*vConfig.Config
	Authorities        map[[32]byte]*vConfig.Authority
	OmitTopology       bool
	DockerImageName    string

	NodeConfigs     []*sConfig.Config
	BasePort        uint16
	LastPort        uint16
	BindAddr        string
	NumVoting       int
	NumServiceNodes int
	NumGateways     int
	NumMixes        int
	NumLayers       int
	nodeIdx         int
	clientIdx       int
	gatewayIdx      int
	serviceNodeIdx  int
	hasPanda        bool
	hasProxy        bool
	NoMixDecoy      bool
	DebugConfig     *cConfig.Debug
}

func (s *Katzenpost) GenConfig() error {
	os.Mkdir(s.OutDir, 0700)
	os.Mkdir(filepath.Join(s.OutDir, s.BaseDir), 0700)

	// Generate the voting authority configurations
	err := s.GenVotingAuthoritiesCfg(s.NumVoting, s.Parameters, s.NumLayers, s.WireKEMScheme)
	if err != nil {
		return err
	}

	// Generate the gateway configs.
	for i := 0; i < s.NumGateways; i++ {
		if err = s.GenNodeConfig(true, false); err != nil {
			return err
		}
	}
	// Generate the service node configs.
	for i := 0; i < s.NumServiceNodes; i++ {
		if err = s.GenNodeConfig(false, true); err != nil {
			return err
		}
	}

	// Generate the mix node configs.
	for i := 0; i < s.NumMixes; i++ {
		if err = s.GenNodeConfig(false, false); err != nil {
			return err
		}
	}
	// Generate the authority config
	gateways, serviceNodes, mixes, err := s.GenAuthorizedNodes()
	if err != nil {
		return err
	}
	for _, vCfg := range s.VotingAuthConfigs {
		vCfg.Mixes = mixes
		vCfg.GatewayNodes = gateways
		vCfg.ServiceNodes = serviceNodes
		if s.OmitTopology == false {
			vCfg.Topology = new(vConfig.Topology)
			vCfg.Topology.Layers = make([]vConfig.Layer, 0)
			for i := 0; i < s.NumLayers; i++ {
				vCfg.Topology.Layers = append(vCfg.Topology.Layers, *new(vConfig.Layer))
				vCfg.Topology.Layers[i].Nodes = make([]vConfig.Node, 0)
			}
			for j := range mixes {
				layer := j % s.NumLayers
				vCfg.Topology.Layers[layer].Nodes = append(vCfg.Topology.Layers[layer].Nodes, *mixes[j])
			}
		}
	}
	for _, vCfg := range s.VotingAuthConfigs {
		if err := saveCfg(vCfg, s.OutDir); err != nil {
			return err
		}
	}

	// write the mixes keys and configs to disk
	for _, v := range s.NodeConfigs {
		if err := saveCfg(v, s.OutDir); err != nil {
			return err
		}
	}

	err = s.GenClientCfg()
	if err != nil {
		return err
	}

	err = s.GenClient2Cfg() // depends on genClientCfg()
	if err != nil {
		return err
	}

	err = s.GenDockerCompose(s.DockerImageName)
	if err != nil {
		return err
	}
	err = s.GenPrometheus()
	if err != nil {
		return err
	}
	return nil
}
