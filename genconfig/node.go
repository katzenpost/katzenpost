package genconfig

import (
	"fmt"
	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	sConfig "github.com/katzenpost/katzenpost/server/config"
	"log"
	"os"
	"path/filepath"
	"sort"
)

func (s *Katzenpost) GenNodeConfig(isGateway, isServiceNode bool) error {
	const serverLogFile = "katzenpost.log"

	n := fmt.Sprintf("mix%d", s.nodeIdx+1)
	if isGateway {
		n = fmt.Sprintf("gateway%d", s.gatewayIdx+1)
	} else if isServiceNode {
		n = fmt.Sprintf("servicenode%d", s.serviceNodeIdx+1)
	}

	cfg := new(sConfig.Config)
	cfg.SphinxGeometry = s.SphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = s.WireKEMScheme
	cfg.Server.PKISignatureScheme = s.PKISignatureScheme.Name()
	cfg.Server.Identifier = n
	if isGateway {
		cfg.Server.Addresses = []string{fmt.Sprintf("http://127.0.0.1:%d", s.LastPort), fmt.Sprintf("tcp://127.0.0.1:%d", s.LastPort+1)}
		s.LastPort += 2
	} else {
		cfg.Server.Addresses = []string{fmt.Sprintf("http://127.0.0.1:%d", s.LastPort)}
		s.LastPort += 1
	}
	cfg.Server.DataDir = filepath.Join(s.BaseDir, n)

	os.Mkdir(filepath.Join(s.OutDir, cfg.Server.Identifier), 0700)

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

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = s.LogLevel

	if isServiceNode {
		// Enable the thwack interface.
		s.serviceNodeIdx++

		// configure an entry provider or a spool storage provider
		cfg.ServiceNode = &sConfig.ServiceNode{}
		spoolCfg := &sConfig.CBORPluginKaetzchen{
			Capability:     "spool",
			Endpoint:       "+spool",
			Command:        s.BaseDir + "/memspool" + s.BinSuffix,
			MaxConcurrency: 1,
			Config: map[string]interface{}{
				"data_store": s.BaseDir + "/" + cfg.Server.Identifier + "/memspool.storage",
				"log_dir":    s.BaseDir + "/" + cfg.Server.Identifier,
			},
		}
		cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{spoolCfg}
		if !s.hasPanda {
			mapCfg := &sConfig.CBORPluginKaetzchen{
				Capability:     "pigeonhole",
				Endpoint:       "+pigeonhole",
				Command:        s.BaseDir + "/pigeonhole" + s.BinSuffix,
				MaxConcurrency: 1,
				Config: map[string]interface{}{
					"db":      s.BaseDir + "/" + cfg.Server.Identifier + "/map.storage",
					"log_dir": s.BaseDir + "/" + cfg.Server.Identifier,
				},
			}

			cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{spoolCfg, mapCfg}
			if !s.hasPanda {
				pandaCfg := &sConfig.CBORPluginKaetzchen{
					Capability:     "panda",
					Endpoint:       "+panda",
					Command:        s.BaseDir + "/panda_server" + s.BinSuffix,
					MaxConcurrency: 1,
					Config: map[string]interface{}{
						"fileStore": s.BaseDir + "/" + cfg.Server.Identifier + "/panda.storage",
						"log_dir":   s.BaseDir + "/" + cfg.Server.Identifier,
						"log_level": s.LogLevel,
					},
				}
				cfg.ServiceNode.CBORPluginKaetzchen = append(cfg.ServiceNode.CBORPluginKaetzchen, pandaCfg)
				s.hasPanda = true
			}

			// Add a single instance of a http proxy for a service listening on port 4242
			if !s.hasProxy {
				proxyCfg := &sConfig.CBORPluginKaetzchen{
					Capability:     "http",
					Endpoint:       "+http",
					Command:        s.BaseDir + "/proxy_server" + s.BinSuffix,
					MaxConcurrency: 1,
					Config: map[string]interface{}{
						// allow connections to localhost:4242
						"host":      "localhost:4242",
						"log_dir":   s.BaseDir + "/" + cfg.Server.Identifier,
						"log_level": "DEBUG",
					},
				}
				cfg.ServiceNode.CBORPluginKaetzchen = append(cfg.ServiceNode.CBORPluginKaetzchen, proxyCfg)
				s.hasProxy = true
			}
			cfg.Debug.NumKaetzchenWorkers = 4
		}

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
	s.NodeConfigs = append(s.NodeConfigs, cfg)
	_ = cfgIdKey(cfg, s.OutDir)
	_ = cfgLinkKey(cfg, s.OutDir, s.WireKEMScheme)
	log.Print("genNodeConfig end")
	return cfg.FixupAndValidate()
}
