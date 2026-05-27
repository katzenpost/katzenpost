// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

// Package genconfig generates Katzenpost mixnet configuration files ostensibly for testing.
// Currently the Katzenpost project uses this package as the main dependency for cmd/genconfig
// which is a CLI tool used by our docker mixnet setup.
package genconfig

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

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
	"github.com/katzenpost/katzenpost/client/thin"
	thinTransport "github.com/katzenpost/katzenpost/client/thin/transport"
	clientTransport "github.com/katzenpost/katzenpost/client/transport"
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
	BasePort               = 30000
	BindAddr               = "0.0.0.0"
	NrLayers               = 3
	NrNodes                = 6
	NrGateways             = 1
	NrServiceNodes         = 1
	NrStorageNodes         = 5
	NrAuthorities          = 3
	ServerLogFile          = "katzenpost.log"
	IdentityPublicKeyFile  = "identity.public.pem"
	IdentityPrivateKeyFile = "identity.private.pem"
	LinkPublicKeyFile      = "link.public.pem"
	LinkPrivateKeyFile     = "link.private.pem"
	CourierService         = "courier"
	ClientIdentifier       = "client"
	DebugLogLevel          = "DEBUG"
	AuthNodeFormat         = "auth%d"
	WritingLogFormat       = "writing %s"

	// DockerNetwork is the bridge network the generated docker-compose puts
	// every katzenpost service on. Each service has a stable container_name
	// matching its identifier, so peers can address each other by DNS name
	// (e.g. tcp://mix1:30030). This lets per-container chaos tools such as
	// pumba install tc qdiscs in each service's own net namespace; the
	// previous host-networked layout had no such namespaces to scope to.
	DockerNetwork    = "katzenpost-net"
	DockerProjectTag = "voting_mixnet"
)

// peerAddr returns the tcp:// URL another container should dial to reach the
// named service on the bridge network. Both endpoints resolve the hostname
// through the compose runtime's embedded DNS to the service's bridge IP.
func peerAddr(identifier string, port uint16) string {
	return fmt.Sprintf("tcp://%s:%d", identifier, port)
}

// metricsScrapeAddr returns the host:port form a service writes into
// its own MetricsAddress field and a remote prometheus scrape dials.
// Inside the service's own container the hostname resolves via the
// compose-managed /etc/hosts entry to its private bridge IP, so the
// prometheus listener binds to that specific private address rather
// than to 0.0.0.0. From a peer container on the same bridge the
// identifier resolves through embedded DNS to the same IP.
func metricsScrapeAddr(identifier string, port uint16) string {
	return fmt.Sprintf("%s:%d", identifier, port)
}

// splitHostPortPort extracts the port portion of a "host:port" string and
// returns it as an integer. Used to rebuild host:port pairs for
// services that need different forms on the listen side and the
// prometheus-scrape side; the host field passed in is discarded.
func splitHostPortPort(hostPort string) (int, error) {
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return 0, fmt.Errorf("invalid host:port %q: %w", hostPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port in %q: %w", hostPort, err)
	}
	return port, nil
}

// Config holds all the parsed command line flags
type Config struct {
	NrLayers                 int
	NrNodes                  int
	NrGateways               int
	NrServiceNodes           int
	NrStorageNodes           int
	Voting                   bool
	NrVoting                 int
	BaseDir                  string
	BasePort                 int
	BindAddr                 string
	OutDir                   string
	DockerImage              string
	BinSuffix                string
	LogLevel                 string
	OmitTopology             bool
	Wirekem                  string
	Kem                      string
	Nike                     string
	UserForwardPayloadLength int
	PkiSignatureScheme       string
	EpochDuration            string
	NoDecoy                  bool
	NoClientDecoy            bool
	NoCourierReplicaDecoy    bool
	NoMixDecoy               bool
	NoGatewayDecoy           bool
	NoMetrics                bool
	PyroscopeDirauth         bool
	PyroscopeKpclientd       bool
	KpclientdMetricsAddress  string
	DialTimeout              int
	MaxPKIDelay              int
	PollingIntvl             int
	Mu                       float64
	LP                       float64
	LL                       float64
	LM                       float64
	LR                       float64
	SchedulerSlack           int
	SchedulerMaxBurst        int
	SendSlack                int
	UnwrapDelay              int
	NumSphinxWorkers         int
	// SessionGracePeriod controls how long kpclientd preserves
	// per-app state after a thin client's socket drops without a
	// thin_close. Parsed from a Go duration string ("30s", "10m");
	// zero means use the compile-time default in client/listener.go.
	SessionGracePeriod time.Duration
}

type Katzenpost struct {
	BaseDir   string
	OutDir    string
	BinSuffix string
	LogLevel  string
	LogWriter io.Writer

	WireKEMScheme      string
	PkiSignatureScheme sign.Scheme
	ReplicaNIKEScheme  nike.Scheme
	SphinxGeometry     *geo.Geometry
	PigeonholeGeometry *pigeonholeGeo.Geometry
	VotingAuthConfigs  []*vConfig.Config
	Authorities        map[[32]byte]*vConfig.Authority
	AuthIdentity       sign.PublicKey

	NodeConfigs        []*sConfig.Config
	ReplicaNodeConfigs []*rConfig.Config
	CourierConfigs     []*courierConfig.Config

	BasePort        uint16
	LastPort        uint16
	LastReplicaPort uint16
	ReplicaNodeIdx  int
	BindAddr        string
	NodeIdx         int
	GatewayIdx      int
	ServiceNodeIdx  int
	NoClientDecoy         bool
	NoCourierReplicaDecoy bool
	NoMixDecoy            bool
	NoGatewayDecoy        bool
	NoMetrics               bool
	PyroscopeDirauth        bool
	PyroscopeKpclientd      bool
	KpclientdMetricsAddress string
	EpochDuration     string
	DebugConfig       *cConfig.Debug
	SchedulerSlack    int
	SchedulerMaxBurst int
	SendSlack         int
	UnwrapDelay       int
	NumSphinxWorkers  int
	// SessionGracePeriod is written into the generated kpclientd
	// client.toml so the daemon's per-app reap interval is tunable
	// per docker invocation; zero means the daemon's compile-time
	// default applies.
	SessionGracePeriod time.Duration
}

type AuthById []*vConfig.Authority

func (a AuthById) Len() int           { return len(a) }
func (a AuthById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a AuthById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type NodeById []*vConfig.Node

func (a NodeById) Len() int           { return len(a) }
func (a NodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a NodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type StorageReplicaNodeById []*vConfig.StorageReplicaNode

func (a StorageReplicaNodeById) Len() int           { return len(a) }
func (a StorageReplicaNodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a StorageReplicaNodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

func AddressesFromURLs(addrs []string) map[string][]string {
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

// thinDialConfigFor builds a thin.Config Dial subtable from a flat
// network/address pair. "unix" maps to [Dial.Unix]; "tcp" / "tcp4" /
// "tcp6" map to [Dial.Tcp] with the explicit Network preserved. Any
// other value is rejected — callers must be explicit.
func thinDialConfigFor(network, addr string) (*thinTransport.DialConfig, error) {
	switch network {
	case "unix":
		return &thinTransport.DialConfig{
			Unix: &thinTransport.UnixDialConfig{Address: addr},
		}, nil
	case "tcp", "tcp4", "tcp6":
		return &thinTransport.DialConfig{
			Tcp: &thinTransport.TcpDialConfig{Address: addr, Network: network},
		}, nil
	default:
		return nil, fmt.Errorf("genconfig: unknown thin-client dial network %q (expected one of: unix, tcp, tcp4, tcp6)", network)
	}
}

// clientListenConfigFor builds a cConfig.Config Listen subtable from a
// flat network/address pair, following the same discriminator rules as
// thinDialConfigFor. Unknown network names are rejected.
func clientListenConfigFor(network, addr string) (*clientTransport.ListenConfig, error) {
	switch network {
	case "unix":
		return &clientTransport.ListenConfig{
			Unix: &clientTransport.UnixListenConfig{Address: addr},
		}, nil
	case "tcp", "tcp4", "tcp6":
		return &clientTransport.ListenConfig{
			Tcp: &clientTransport.TcpListenConfig{Address: addr, Network: network},
		}, nil
	default:
		return nil, fmt.Errorf("genconfig: unknown kpclientd listen network %q (expected one of: unix, tcp, tcp4, tcp6)", network)
	}
}

// this generates the thin client config and NOT the client daemon config
func (s *Katzenpost) GenClient2ThinCfg(net, addr string) error {
	log.Print("genClient2ThinCfg begin")
	os.MkdirAll(filepath.Join(s.OutDir, "client"), 0700)
	cfg := new(thin.Config)

	// Geometry is no longer written to the thin client config: the
	// daemon delivers it over the handshake. The generated
	// thinclient.toml carries only the [Dial] section.
	dial, err := thinDialConfigFor(net, addr)
	if err != nil {
		return err
	}
	cfg.Dial = dial

	log.Print("before save thin config")
	err = SaveCfg(cfg, s.OutDir)
	if err != nil {
		log.Printf("save thin config failure %s", err.Error())
		return err
	}
	log.Print("after save thin config")
	log.Print("GenClient2ThinCfg end")
	return nil
}

func (s *Katzenpost) GenClient2Cfg(net, addr string) error {
	log.Print("genClient2Cfg begin")
	os.MkdirAll(filepath.Join(s.OutDir, "client"), 0700)
	os.MkdirAll(filepath.Join(s.OutDir, "thinclient"), 0700)

	cfg := new(cConfig.Config)

	// Use TCP by default so that the CI tests pass on all platforms
	listen, err := clientListenConfigFor(net, addr)
	if err != nil {
		return err
	}
	cfg.Listen = listen

	// Logging section.
	cfg.Logging = &cConfig.Logging{File: "", Level: DebugLogLevel}

	cfg.PKISignatureScheme = s.PkiSignatureScheme.Name()
	cfg.WireKEMScheme = s.WireKEMScheme
	cfg.SphinxGeometry = s.SphinxGeometry
	cfg.PigeonholeGeometry = s.PigeonholeGeometry
	// Docker-mixnet kpclientd reaches gateways and dirauths by
	// container hostname through the compose-runtime's embedded
	// DNS; opt in to hostname-permitting validation.
	cfg.AllowHostnameAddresses = true

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
	cfg.Debug = &cConfig.Debug{DisableDecoyTraffic: s.DebugConfig.DisableDecoyTraffic}

	// SessionGracePeriod controls how long the daemon preserves
	// per-app state after a thin client's connection drops without
	// thin_close. Zero means the daemon's compile-time default
	// (currently ten minutes) applies; the docker Makefile sets a
	// shorter value via --sessionGracePeriod so the reaper visibly
	// exercises within a single CI run.
	if s.SessionGracePeriod > 0 {
		cfg.SessionGracePeriod = s.SessionGracePeriod
	}

	// Metrics listener: only written into client.toml when the operator
	// has chosen to enable it via --kpclientdMetricsAddress, which the
	// docker Makefile turns on when kpclientd_metrics=true.
	// Production builds of kpclientd ignore this field entirely
	// because the listener is gated behind a build tag.
	//
	// Under bridge networking we discard whatever host portion was
	// passed in and bind to the kpclientd container's own private
	// bridge IP (reached via its `kpclientd` hostname). The prometheus
	// container scrapes it as `kpclientd:<port>` over the same bridge.
	if s.KpclientdMetricsAddress != "" {
		port, err := splitHostPortPort(s.KpclientdMetricsAddress)
		if err != nil {
			return err
		}
		cfg.MetricsAddress = metricsScrapeAddr("kpclientd", uint16(port))
	}

	gateways := make([]*cConfig.Gateway, 0)
	for i := 0; i < len(s.NodeConfigs); i++ {
		if s.NodeConfigs[i].Gateway == nil {
			continue
		}

		idPubKey := CfgIdKey(s.NodeConfigs[i], s.OutDir)
		linkPubKey := CfgLinkKey(s.NodeConfigs[i], s.OutDir, cfg.WireKEMScheme)

		gateway := &cConfig.Gateway{
			PKISignatureScheme: s.PkiSignatureScheme.Name(),
			WireKEMScheme:      s.WireKEMScheme,
			Name:               s.NodeConfigs[i].Server.Identifier,
			IdentityKey:        idPubKey,
			LinkKey:            cConfig.LinkPublicKey{PublicKey: linkPubKey},
			Addresses:          s.NodeConfigs[i].Server.Addresses,
		}
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		panic("wtf 0 gateways")
	}
	cfg.PinnedGateways = &cConfig.Gateways{
		Gateways: gateways,
	}
	err = SaveCfg(cfg, s.OutDir)
	if err != nil {
		log.Printf("save client config failure %s", err.Error())
		return err
	}
	return nil
}

func Write(f *os.File, str string, args ...interface{}) {
	str = fmt.Sprintf(str, args...)
	_, err := f.WriteString(str)

	if err != nil {
		log.Fatal(err)
	}
}

func (s *Katzenpost) GenCourierConfig(datadir string, serviceNodeName string) *courierConfig.Config {
	authorities := make([]*vConfig.Authority, 0, len(s.Authorities))
	i := 0
	for _, auth := range s.Authorities {
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
	cfg := &courierConfig.Config{
		PKI:                    pki,
		Logging:                &courierConfig.Logging{File: logPath, Level: DebugLogLevel},
		WireKEMScheme:          s.WireKEMScheme,
		PKIScheme:              s.PkiSignatureScheme.Name(),
		EnvelopeScheme:         s.ReplicaNIKEScheme.Name(),
		DataDir:                datadir,
		SphinxGeometry:         s.SphinxGeometry,
		ConnectTimeout:         config.DefaultConnectTimeout,
		HandshakeTimeout:       config.DefaultHandshakeTimeout,
		ReauthInterval:         config.DefaultReauthInterval,
		DisableDecoyTraffic:    s.NoCourierReplicaDecoy,
		AllowHostnameAddresses: true, // docker-mixnet uses container hostnames
	}
	cfg.MetricsAddress = metricsScrapeAddr(serviceNodeName, s.LastPort)
	s.LastPort++
	return cfg
}

func (s *Katzenpost) GenReplicaNodeConfig() error {
	log.Print("GenReplicaNodeConfig")

	cfg := new(rConfig.Config)

	cfg.Identifier = fmt.Sprintf("replica%d", s.ReplicaNodeIdx+1)
	cfg.ReplicaID = uint8(s.ReplicaNodeIdx)
	cfg.SphinxGeometry = s.SphinxGeometry
	cfg.WireKEMScheme = s.WireKEMScheme
	cfg.ReplicaNIKEScheme = s.ReplicaNIKEScheme.Name()
	cfg.PKISignatureScheme = s.PkiSignatureScheme.Name()
	// Docker-mixnet replicas address dirauths and peers by container
	// hostname; opt in to hostname-permitting validation.
	cfg.AllowHostnameAddresses = true

	cfg.Addresses = []string{peerAddr(cfg.Identifier, s.LastReplicaPort)}
	s.LastReplicaPort++

	cfg.MetricsAddress = metricsScrapeAddr(cfg.Identifier, s.LastReplicaPort)
	s.LastReplicaPort++

	cfg.DataDir = filepath.Join(s.BaseDir, cfg.Identifier)
	os.MkdirAll(filepath.Join(s.OutDir, cfg.Identifier), 0700)

	// Set timeout values explicitly to use common config defaults
	cfg.ConnectTimeout = config.DefaultConnectTimeout
	cfg.HandshakeTimeout = config.DefaultHandshakeTimeout
	cfg.ReauthInterval = config.DefaultReauthInterval
	cfg.DisableDecoyTraffic = s.NoCourierReplicaDecoy

	authorities := make([]*vConfig.Authority, 0, len(s.Authorities))
	i := 0
	for _, auth := range s.Authorities {
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
	cfg.Logging.File = ServerLogFile
	//cfg.Logging.Level = s.LogLevel
	cfg.Logging.Level = DebugLogLevel

	s.ReplicaNodeConfigs = append(s.ReplicaNodeConfigs, cfg)
	_ = CfgIdKey(cfg, s.OutDir)
	_ = CfgLinkKey(cfg, s.OutDir, s.WireKEMScheme)

	s.ReplicaNodeIdx++
	return cfg.FixupAndValidate(false)
}

func (s *Katzenpost) GenNodeConfig(isGateway, isServiceNode bool, isVoting bool) error {
	n := fmt.Sprintf("mix%d", s.NodeIdx+1)
	if isGateway {
		n = fmt.Sprintf("gateway%d", s.GatewayIdx+1)
	} else if isServiceNode {
		n = fmt.Sprintf("servicenode%d", s.ServiceNodeIdx+1)
	}

	cfg := new(sConfig.Config)
	cfg.SphinxGeometry = s.SphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = s.WireKEMScheme
	cfg.Server.PKISignatureScheme = s.PkiSignatureScheme.Name()
	cfg.Server.Identifier = n
	// Both the advertise address (Addresses, used by peers via the
	// embedded bridge DNS) and the bind address (BindAddresses, used
	// by net.Listen) point at the service's own hostname. Inside the
	// container that resolves to the private bridge IP via /etc/hosts,
	// so we never bind to 0.0.0.0.
	cfg.Server.Addresses = []string{peerAddr(n, s.LastPort)}
	cfg.Server.BindAddresses = []string{peerAddr(n, s.LastPort)}
	s.LastPort += 2
	cfg.Server.DataDir = filepath.Join(s.BaseDir, n)

	os.MkdirAll(filepath.Join(s.OutDir, cfg.Server.Identifier), 0700)

	cfg.Server.IsGatewayNode = isGateway
	cfg.Server.IsServiceNode = isServiceNode
	// Generated configs live on the docker-mixnet's bridge network
	// where peers address one another by container hostname; opt in
	// to hostname-permitting validation for every emitted TOML so
	// production parity is maintained (operators never use genconfig
	// to produce production configs).
	cfg.Server.AllowHostnameAddresses = true
	if isGateway {
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true
	}
	if isServiceNode {
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true
	}
	// Enable Metrics endpoint
	cfg.Server.MetricsAddress = metricsScrapeAddr(n, s.LastPort)
	s.LastPort += 1

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	// Decoy emission is governed by separate switches for gateway and
	// internal-mix roles so that the coupon-collector decoys at the
	// gateway can be exercised independently of the mix-layer decoys.
	// Service nodes do not run the decoy worker, so the value selected
	// here is moot for them.
	if isGateway {
		cfg.Debug.SendDecoyTraffic = !s.NoGatewayDecoy
	} else {
		cfg.Debug.SendDecoyTraffic = !s.NoMixDecoy
	}
	if s.SchedulerSlack > 0 {
		cfg.Debug.SchedulerSlack = s.SchedulerSlack
	}
	if s.SchedulerMaxBurst > 0 {
		cfg.Debug.SchedulerMaxBurst = s.SchedulerMaxBurst
	}
	if s.SendSlack > 0 {
		cfg.Debug.SendSlack = s.SendSlack
	}
	if s.UnwrapDelay > 0 {
		cfg.Debug.UnwrapDelay = s.UnwrapDelay
	}
	if s.NumSphinxWorkers > 0 {
		cfg.Debug.NumSphinxWorkers = s.NumSphinxWorkers
	}

	// PKI section.
	if isVoting {
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
	}

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = ServerLogFile
	cfg.Logging.Level = s.LogLevel

	if isServiceNode {
		// Enable the thwack interface.
		s.ServiceNodeIdx++

		cfg.ServiceNode = &sConfig.ServiceNode{}

		serviceNodeDataDir := filepath.Join(s.OutDir, cfg.Server.Identifier)
		courierDataDir := filepath.Join(serviceNodeDataDir, CourierService)
		os.MkdirAll(courierDataDir, 0700)

		internalCourierDatadir := filepath.Join(s.BaseDir, cfg.Server.Identifier, CourierService)
		courierCfg := s.GenCourierConfig(internalCourierDatadir, cfg.Server.Identifier)
		s.CourierConfigs = append(s.CourierConfigs, courierCfg)

		linkPubKey := CfgLinkKey(courierCfg, courierDataDir, courierCfg.WireKEMScheme)
		linkBlob := kempem.ToPublicPEMString(linkPubKey)

		err := SaveCfg(courierCfg, serviceNodeDataDir)
		if err != nil {
			return fmt.Errorf("failed to write courier config: %s", err)
		}
		advertizeableCourierCfgPath := s.BaseDir + "/" + cfg.Server.Identifier + "/" + CourierService + "/courier.toml"
		advert := make(map[string]map[string]interface{})
		advert[CourierService] = make(map[string]interface{})
		advert[CourierService]["linkPublicKey"] = linkBlob

		// "courier" service is described in our paper, it's used to communicate
		// with the storage replicas to form the Pigeonhole storage system.
		courierPluginCfg := &sConfig.CBORPluginKaetzchen{
			Capability:        CourierService,
			Endpoint:          CourierService,
			Command:           s.BaseDir + "/courier" + s.BinSuffix,
			MaxConcurrency:    1,
			PKIAdvertizedData: advert,
			Config: map[string]interface{}{
				"c": advertizeableCourierCfgPath,
			},
		}

		proxyCfg := &sConfig.CBORPluginKaetzchen{
			Capability:     "http",
			Endpoint:       "+http",
			Command:        s.BaseDir + "/proxy_server" + s.BinSuffix,
			MaxConcurrency: 1,
			Config: map[string]interface{}{
				// allow connections to localhost:4242
				"host":      "localhost:4242",
				"log_dir":   s.BaseDir + "/" + cfg.Server.Identifier,
				"log_level": DebugLogLevel,
			},
		}

		cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{courierPluginCfg, proxyCfg}

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
		s.GatewayIdx++
		cfg.Gateway = &sConfig.Gateway{}
	} else {
		s.NodeIdx++
	}
	s.NodeConfigs = append(s.NodeConfigs, cfg)
	_ = CfgIdKey(cfg, s.OutDir)
	_ = CfgLinkKey(cfg, s.OutDir, s.WireKEMScheme)
	log.Print("GenNodeConfig end")
	return cfg.FixupAndValidate()
}

func (s *Katzenpost) GenVotingAuthoritiesCfg(numAuthorities int, parameters *vConfig.Parameters, nrLayers int, wirekem string) error {

	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	s.Authorities = make(map[[32]byte]*vConfig.Authority)
	for i := 1; i <= numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.SphinxGeometry = s.SphinxGeometry
		authIdentifier := fmt.Sprintf(AuthNodeFormat, i)
		cfg.Server = &vConfig.Server{
			WireKEMScheme:          s.WireKEMScheme,
			PKISignatureScheme:     s.PkiSignatureScheme.Name(),
			AllowHostnameAddresses: true, // docker-mixnet uses container hostnames
			Identifier:         authIdentifier,
			Addresses:          []string{peerAddr(authIdentifier, s.LastPort)},
			DataDir:            filepath.Join(s.BaseDir, authIdentifier),
		}
		os.MkdirAll(filepath.Join(s.OutDir, cfg.Server.Identifier), 0700)
		s.LastPort += 1
		// Allocate a metrics listener port for this dirauth. The
		// prometheus listener in the dirauth code only binds when
		// MetricsAddress is non-empty, so a future operator who wants
		// to disable it can leave the field empty post-genconfig.
		cfg.Server.MetricsAddress = metricsScrapeAddr(authIdentifier, s.LastPort)
		s.LastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    ServerLogFile,
			Level:   s.LogLevel,
		}
		cfg.Parameters = parameters
		cfg.Debug = &vConfig.Debug{
			Layers:           nrLayers,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		idKey := CfgIdKey(cfg, s.OutDir)
		linkKey := CfgLinkKey(cfg, s.OutDir, wirekem)
		authority := &vConfig.Authority{
			Identifier:         fmt.Sprintf(AuthNodeFormat, i),
			IdentityPublicKey:  idKey,
			LinkPublicKey:      vConfig.LinkPublicKey{PublicKey: linkKey},
			WireKEMScheme:      wirekem,
			PKISignatureScheme: s.PkiSignatureScheme.Name(),
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

func (s *Katzenpost) GenAuthorizedNodes() ([]*vConfig.StorageReplicaNode, []*vConfig.Node, []*vConfig.Node, []*vConfig.Node, error) {
	replicas := []*vConfig.StorageReplicaNode{}
	for _, replicaCfg := range s.ReplicaNodeConfigs {
		node := &vConfig.StorageReplicaNode{
			Identifier:           replicaCfg.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", replicaCfg.Identifier, IdentityPublicKeyFile),
			ReplicaID:            replicaCfg.ReplicaID,
		}
		replicas = append(replicas, node)
	}

	mixes := []*vConfig.Node{}
	gateways := []*vConfig.Node{}
	serviceNodes := []*vConfig.Node{}
	for _, nodeCfg := range s.NodeConfigs {
		node := &vConfig.Node{
			Identifier:           nodeCfg.Server.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, IdentityPublicKeyFile),
		}
		if nodeCfg.Server.IsGatewayNode {
			gateways = append(gateways, node)
		} else if nodeCfg.Server.IsServiceNode {
			serviceNodes = append(serviceNodes, node)
		} else {
			mixes = append(mixes, node)
		}
	}

	sort.Sort(StorageReplicaNodeById(replicas))
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(gateways))
	sort.Sort(NodeById(serviceNodes))

	return replicas, gateways, serviceNodes, mixes, nil
}

// RunGenConfig executes the main configuration generation logic
func RunGenConfig(cfg Config) error {
	// Validate configuration
	if err := ValidateConfig(&cfg); err != nil {
		return err
	}

	// Create parameters struct for voting authorities. Sampling
	// safety caps are derived inside the library from each rate, so
	// no MaxDelay companion fields are written here.
	parameters := &vConfig.Parameters{
		Mu:      cfg.Mu,
		LambdaP: cfg.LP,
		LambdaL: cfg.LL,
		LambdaM: cfg.LM,
		LambdaR: cfg.LR,
	}

	// Initialize katzenpost struct
	s := InitializeKatzenpost(&cfg)

	// Setup cryptographic schemes and geometries
	if err := SetupGeometry(s, &cfg); err != nil {
		return err
	}

	// Create output directories
	os.MkdirAll(s.OutDir, 0700)
	os.MkdirAll(filepath.Join(s.OutDir, s.BaseDir), 0700)

	// Generate voting authority configurations if needed
	if cfg.Voting {
		if err := s.GenVotingAuthoritiesCfg(cfg.NrVoting, parameters, cfg.NrLayers, cfg.Wirekem); err != nil {
			return fmt.Errorf("getVotingAuthoritiesCfg failed: %s", err)
		}
	}

	// Generate all node configurations
	if err := GenerateNodes(s, &cfg); err != nil {
		return err
	}

	// Configure voting authorities and topology
	if err := ConfigureAuthorities(s, &cfg); err != nil {
		return err
	}

	// Save all configurations to disk
	if err := SaveConfigurations(s, &cfg); err != nil {
		return err
	}

	// Generate client configurations
	if err := GenerateClientConfigurations(s); err != nil {
		return err
	}

	// Generate output files (docker-compose, prometheus)
	if err := GenerateOutputFiles(s, &cfg); err != nil {
		return err
	}

	return nil
}

// ValidateConfig validates the parsed configuration and returns any errors
func ValidateConfig(cfg *Config) error {
	if cfg.Wirekem == "" {
		return fmt.Errorf("wire KEM must be set")
	}

	if cfg.Kem == "" && cfg.Nike == "" {
		return fmt.Errorf("either nike or kem must be set")
	}
	if cfg.Kem != "" && cfg.Nike != "" {
		return fmt.Errorf("nike and kem flags cannot both be set")
	}

	if kemschemes.ByName(cfg.Wirekem) == nil {
		return fmt.Errorf("invalid wire KEM scheme")
	}

	return nil
}

// InitializeKatzenpost creates and initializes a Katzenpost struct with the given configuration
func InitializeKatzenpost(cfg *Config) *Katzenpost {
	s := &Katzenpost{}

	s.WireKEMScheme = cfg.Wirekem
	s.BaseDir = cfg.BaseDir
	s.OutDir = cfg.OutDir
	s.BinSuffix = cfg.BinSuffix
	s.BasePort = uint16(cfg.BasePort)
	s.LastPort = s.BasePort + 1
	// Replicas are allotted their own port range so they remain
	// distinguishable from the mix and authority listeners. The offset is
	// kept modest (1000 rather than 3000) so that with the default
	// BasePort of 30000 the replicas land at 31000+ rather than 33000+.
	// On Linux the default ephemeral source-port range begins at 32768,
	// so a listener at 33000 may collide with an outbound connection that
	// happened to be assigned that source port first; the resulting bind
	// failure aborts replica startup and yields flaky CI runs. Holding
	// the replica band beneath 32768 avoids that race.
	s.LastReplicaPort = s.BasePort + 1000
	s.BindAddr = cfg.BindAddr
	s.LogLevel = cfg.LogLevel
	s.DebugConfig = &cConfig.Debug{
		DisableDecoyTraffic:         cfg.NoDecoy || cfg.NoClientDecoy,
		SessionDialTimeout:          cfg.DialTimeout,
		InitialMaxPKIRetrievalDelay: cfg.MaxPKIDelay,
		PollingInterval:             cfg.PollingIntvl,
	}
	s.NoClientDecoy = cfg.NoDecoy || cfg.NoClientDecoy
	s.NoCourierReplicaDecoy = cfg.NoDecoy || cfg.NoCourierReplicaDecoy
	s.NoMixDecoy = cfg.NoMixDecoy
	s.NoGatewayDecoy = cfg.NoGatewayDecoy
	s.NoMetrics = cfg.NoMetrics
	s.PyroscopeDirauth = cfg.PyroscopeDirauth
	s.PyroscopeKpclientd = cfg.PyroscopeKpclientd
	s.KpclientdMetricsAddress = cfg.KpclientdMetricsAddress
	s.EpochDuration = cfg.EpochDuration
	s.SchedulerSlack = cfg.SchedulerSlack
	s.SchedulerMaxBurst = cfg.SchedulerMaxBurst
	s.SendSlack = cfg.SendSlack
	s.UnwrapDelay = cfg.UnwrapDelay
	s.NumSphinxWorkers = cfg.NumSphinxWorkers
	s.SessionGracePeriod = cfg.SessionGracePeriod

	return s
}

// SetupGeometry configures the cryptographic schemes and geometries
func SetupGeometry(s *Katzenpost, cfg *Config) error {
	nrHops := cfg.NrLayers + 2

	if cfg.Nike != "" {
		nikeScheme := schemes.ByName(cfg.Nike)
		if nikeScheme == nil {
			return fmt.Errorf("failed to resolve nike scheme %s", cfg.Nike)
		}
		s.SphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.Kem != "" {
		kemScheme := kemschemes.ByName(cfg.Kem)
		if kemScheme == nil {
			return fmt.Errorf("failed to resolve kem scheme %s", cfg.Kem)
		}
		s.SphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.PkiSignatureScheme != "" {
		signScheme := signSchemes.ByName(cfg.PkiSignatureScheme)
		if signScheme == nil {
			return fmt.Errorf("failed to resolve pki signature scheme %s", cfg.PkiSignatureScheme)
		}
		s.PkiSignatureScheme = signScheme
	}

	s.ReplicaNIKEScheme = replicaCommon.NikeScheme

	// Generate pigeonhole geometry once for use in both client and thin client configs
	var err error
	s.PigeonholeGeometry, err = pigeonholeGeo.NewGeometryFromSphinx(s.SphinxGeometry, s.ReplicaNIKEScheme)
	if err != nil {
		return fmt.Errorf("failed to create pigeonhole geometry: %v", err)
	}

	return nil
}

// GenerateNodes creates all the different types of nodes (gateways, service nodes, mixes, replicas)
func GenerateNodes(s *Katzenpost, cfg *Config) error {
	// Generate the gateway configs.
	for i := 0; i < cfg.NrGateways; i++ {
		if err := s.GenNodeConfig(true, false, cfg.Voting); err != nil {
			return fmt.Errorf("failed to generate gateway config: %v", err)
		}
	}

	// Generate the service node configs.
	for i := 0; i < cfg.NrServiceNodes; i++ {
		if err := s.GenNodeConfig(false, true, cfg.Voting); err != nil {
			return fmt.Errorf("failed to generate service node config: %v", err)
		}
	}

	// Generate the mix node configs.
	for i := 0; i < cfg.NrNodes; i++ {
		if err := s.GenNodeConfig(false, false, cfg.Voting); err != nil {
			return fmt.Errorf("failed to generate mix node config: %v", err)
		}
	}

	// Pigeonhole storage replica node configs.
	for i := 0; i < cfg.NrStorageNodes; i++ {
		if err := s.GenReplicaNodeConfig(); err != nil {
			return fmt.Errorf("failed to generate storage replica node config: %v", err)
		}
	}

	return nil
}

// ConfigureAuthorities handles voting authority configuration and topology setup
func ConfigureAuthorities(s *Katzenpost, cfg *Config) error {
	if !cfg.Voting {
		return nil
	}

	replicas, gateways, serviceNodes, mixes, err := s.GenAuthorizedNodes()
	if err != nil {
		return fmt.Errorf("failed to generate authorized nodes: %v", err)
	}

	for _, vCfg := range s.VotingAuthConfigs {
		for _, k := range replicas {
			vCfg.StorageReplicas = append(vCfg.StorageReplicas, k)
		}
		vCfg.Mixes = mixes
		vCfg.GatewayNodes = gateways
		vCfg.ServiceNodes = serviceNodes

		if !cfg.OmitTopology {
			vCfg.Topology = new(vConfig.Topology)
			vCfg.Topology.Layers = make([]vConfig.Layer, 0)
			for i := 0; i < cfg.NrLayers; i++ {
				vCfg.Topology.Layers = append(vCfg.Topology.Layers, *new(vConfig.Layer))
				vCfg.Topology.Layers[i].Nodes = make([]vConfig.Node, 0)
			}
			for j := range mixes {
				layer := j % cfg.NrLayers
				vCfg.Topology.Layers[layer].Nodes = append(vCfg.Topology.Layers[layer].Nodes, *mixes[j])
			}
		}
	}

	return nil
}

// SaveConfigurations saves all generated configurations to disk
func SaveConfigurations(s *Katzenpost, cfg *Config) error {
	// Save voting authority configs
	if cfg.Voting {
		for _, vCfg := range s.VotingAuthConfigs {
			if err := SaveCfg(vCfg, cfg.OutDir); err != nil {
				return fmt.Errorf("failed to SaveCfg of authority: %v", err)
			}
		}
	}

	// Save node configs
	for _, v := range s.NodeConfigs {
		if err := SaveCfg(v, cfg.OutDir); err != nil {
			return fmt.Errorf("SaveCfg failure: %v", err)
		}
	}

	// Save replica configs
	for _, r := range s.ReplicaNodeConfigs {
		if err := SaveCfg(r, cfg.OutDir); err != nil {
			return fmt.Errorf("SaveCfg failure: %v", err)
		}
	}

	return nil
}

// GenerateClientConfigurations creates all client configuration files.
// The kpclientd daemon and the thin clients that talk to it sit at
// opposite ends of the docker-compose port publish, so they need
// different addresses. The daemon binds to its own private bridge IP
// (reached via its `kpclientd` hostname), and the docker port publish
// forwards host:64331 to that same bridge address. The thin clients
// (ping, fetch) run on the host with --network=host and dial
// localhost:64331 over the published port; the host's /etc/hosts
// resolves localhost to 127.0.0.1 and the published forward picks it
// up.
func GenerateClientConfigurations(s *Katzenpost) error {
	clientDaemonNetwork := "tcp"
	clientDaemonListenAddress := "kpclientd:64331"
	clientDaemonDialAddress := "localhost:64331"

	err := s.GenClient2Cfg(clientDaemonNetwork, clientDaemonListenAddress)
	if err != nil {
		return fmt.Errorf("failed to generate client config: %v", err)
	}

	err = s.GenClient2ThinCfg(clientDaemonNetwork, clientDaemonDialAddress)
	if err != nil {
		return fmt.Errorf("failed to generate client thin config: %v", err)
	}

	return nil
}

// GenerateOutputFiles creates docker-compose and prometheus configuration files
func GenerateOutputFiles(s *Katzenpost, cfg *Config) error {
	err := s.GenDockerCompose(cfg.DockerImage)
	if err != nil {
		return fmt.Errorf("failed to generate docker-compose: %v", err)
	}

	if !s.NoMetrics {
		err = s.GenPrometheus()
		if err != nil {
			return fmt.Errorf("failed to generate prometheus config: %v", err)
		}

		err = s.GenGrafana()
		if err != nil {
			return fmt.Errorf("failed to generate grafana config: %v", err)
		}
	}

	return nil
}

func Identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return ClientIdentifier
	case *thin.Config:
		return ClientIdentifier
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Server.Identifier
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *rConfig.Config:
		return cfg.(*rConfig.Config).Identifier
	case *courierConfig.Config:
		return CourierService
	default:
		log.Fatalf("identifier() passed unexpected type %v", cfg)
		return ""
	}
}

func TomlName(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return ClientIdentifier
	case *thin.Config:
		return "thinclient"
	case *sConfig.Config:
		return "katzenpost"
	case *rConfig.Config:
		return "replica"
	case *courierConfig.Config:
		return CourierService
	case *vConfig.Config:
		return "authority"
	default:
		log.Fatalf("tomlName() passed unexpected type")
		return ""
	}
}

func SaveCfg(cfg interface{}, outDir string) error {
	fileName := filepath.Join(outDir, Identifier(cfg), fmt.Sprintf("%s.toml", TomlName(cfg)))
	log.Printf(WritingLogFormat, fileName)
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("os.Create(%s) failed: %s", fileName, err)
	}
	defer f.Close()

	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

func CfgIdKey(cfg interface{}, outDir string) sign.PublicKey {
	var priv, public string
	var pkiSignatureScheme string
	switch cfg.(type) {
	case *rConfig.Config:
		priv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, IdentityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, IdentityPublicKeyFile)
		pkiSignatureScheme = cfg.(*rConfig.Config).PKISignatureScheme
	case *sConfig.Config:
		priv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, IdentityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, IdentityPublicKeyFile)
		pkiSignatureScheme = cfg.(*sConfig.Config).Server.PKISignatureScheme
	case *vConfig.Config:
		priv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, IdentityPrivateKeyFile)
		public = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, IdentityPublicKeyFile)
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
	log.Printf(WritingLogFormat, priv)
	signpem.PrivateKeyToFile(priv, idKey)
	log.Printf(WritingLogFormat, public)
	signpem.PublicKeyToFile(public, idPubKey)
	return idPubKey
}

func CfgLinkKey(cfg interface{}, outDir string, kemScheme string) kem.PublicKey {
	var linkpriv string
	var linkpublic string

	switch cfg.(type) {
	case *rConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*rConfig.Config).Identifier, LinkPublicKeyFile)
	case *sConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, LinkPublicKeyFile)
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, LinkPublicKeyFile)
	case *courierConfig.Config:
		linkpriv = filepath.Join(outDir, LinkPrivateKeyFile)
		linkpublic = filepath.Join(outDir, LinkPublicKeyFile)
	default:
		panic("wrong type")
	}

	linkPubKey, linkPrivKey, err := kemschemes.ByName(kemScheme).GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	log.Printf(WritingLogFormat, linkpriv)
	err = kempem.PrivateKeyToFile(linkpriv, linkPrivKey)
	if err != nil {
		panic(err)
	}
	log.Printf(WritingLogFormat, linkpublic)
	err = kempem.PublicKeyToFile(linkpublic, linkPubKey)
	if err != nil {
		panic(err)
	}
	return linkPubKey
}

func (s *Katzenpost) GenPrometheus() error {
	dest := filepath.Join(s.OutDir, "prometheus.yml")
	log.Printf(WritingLogFormat, dest)

	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	Write(f, `
scrape_configs:
`)

	for _, cfg := range s.ReplicaNodeConfigs {
		Write(f, `- job_name: %s
  scrape_interval: 1s
  static_configs:
  - targets: ['%s']
`, cfg.Identifier, cfg.MetricsAddress)
	}
	for i, cfg := range s.CourierConfigs {
		Write(f, `- job_name: courier%d
  scrape_interval: 1s
  static_configs:
  - targets: ['%s']
`, i+1, cfg.MetricsAddress)
	}
	for _, cfg := range s.NodeConfigs {
		Write(f, `- job_name: %s
  scrape_interval: 1s
  static_configs:
  - targets: ['%s']
`, cfg.Server.Identifier, cfg.Server.MetricsAddress)
	}
	for _, cfg := range s.VotingAuthConfigs {
		if cfg.Server.MetricsAddress == "" {
			continue
		}
		Write(f, `- job_name: %s
  scrape_interval: 1s
  static_configs:
  - targets: ['%s']
`, cfg.Server.Identifier, cfg.Server.MetricsAddress)
	}
	if s.KpclientdMetricsAddress != "" {
		port, err := splitHostPortPort(s.KpclientdMetricsAddress)
		if err != nil {
			return err
		}
		Write(f, `- job_name: kpclientd
  scrape_interval: 1s
  static_configs:
  - targets: ['%s']
`, metricsScrapeAddr("kpclientd", uint16(port)))
	}
	// parallel-load is an opt-in ad-hoc container launched by `make
	// run-parallel-load`; the host name `parallel-load` resolves only
	// while the container is alive. Prometheus will report up=0 on this
	// target between runs, which is the intended UX: the panel becomes
	// non-empty exactly when a load run is in progress.
	Write(f, `- job_name: parallel-load
  scrape_interval: 1s
  static_configs:
  - targets: ['parallel-load:9101']
`)
	return nil
}

func (s *Katzenpost) GenGrafana() error {
	grafanaDir := filepath.Join(s.OutDir, "grafana")
	dsDir := filepath.Join(grafanaDir, "provisioning", "datasources")
	dbProvDir := filepath.Join(grafanaDir, "provisioning", "dashboards")
	dbDir := filepath.Join(grafanaDir, "dashboards")
	os.MkdirAll(dsDir, 0755)
	os.MkdirAll(dbProvDir, 0755)
	os.MkdirAll(dbDir, 0755)

	// Datasource config
	dsFile := filepath.Join(dsDir, "prometheus.yml")
	log.Printf(WritingLogFormat, dsFile)
	ds, err := os.Create(dsFile)
	if err != nil {
		return err
	}
	defer ds.Close()
	Write(ds, `apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://metrics:9090
    isDefault: true
    editable: false
`)

	// Dashboard provisioning config
	dbProvFile := filepath.Join(dbProvDir, "dashboards.yml")
	log.Printf(WritingLogFormat, dbProvFile)
	dbProv, err := os.Create(dbProvFile)
	if err != nil {
		return err
	}
	defer dbProv.Close()
	Write(dbProv, `apiVersion: 1
providers:
  - name: Default
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
`)

	// Dashboard JSON
	dbFile := filepath.Join(dbDir, "katzenpost.json")
	log.Printf(WritingLogFormat, dbFile)
	db, err := os.Create(dbFile)
	if err != nil {
		return err
	}
	defer db.Close()
	Write(db, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Katzenpost Courier & Replica",
  "uid": "katzenpost-decoy",
  "version": 2,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "Courier: Decoys Sent (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0},
      "targets": [{"expr": "rate(katzenpost_courier_decoys_sent_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 2,
      "title": "Courier: Messages Sent (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 8, "y": 0},
      "targets": [{"expr": "rate(katzenpost_courier_messages_sent_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 3,
      "title": "Courier: Messages Received (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 16, "y": 0},
      "targets": [{"expr": "rate(katzenpost_courier_messages_received_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 4,
      "title": "Courier: Queue Length per Replica",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
      "targets": [{"expr": "katzenpost_courier_queue_length", "refId": "A", "legendFormat": "{{job}} - {{replica}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 5,
      "title": "Replica: Incoming Decoys Received (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 0, "y": 16},
      "targets": [{"expr": "rate(katzenpost_replica_incoming_decoys_received_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 6,
      "title": "Replica: Incoming Decoy Replies Emitted (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 8, "y": 16},
      "targets": [{"expr": "rate(katzenpost_replica_incoming_decoy_replies_emitted_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 7,
      "title": "Replica: Incoming Real Replies Emitted (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 16, "y": 16},
      "targets": [{"expr": "rate(katzenpost_replica_incoming_real_replies_emitted_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 8,
      "title": "Replica: Outgoing Decoys Sent (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 0, "y": 24},
      "targets": [{"expr": "rate(katzenpost_replica_outgoing_decoys_sent_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 9,
      "title": "Replica: Outgoing Messages Sent (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 8, "y": 24},
      "targets": [{"expr": "rate(katzenpost_replica_outgoing_messages_sent_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 10,
      "title": "Replica: Replication Dispatched (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 16, "y": 24},
      "targets": [{"expr": "rate(katzenpost_replica_replication_dispatched_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 11,
      "title": "Replica: Incoming Queue Length per Peer (M/M/1 backlog diagnostic)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
      "targets": [{"expr": "katzenpost_replica_incoming_queue_length", "refId": "A", "legendFormat": "{{job}} - {{peer}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 12,
      "title": "Replica: Outgoing Queue Length per Peer (LambdaR drain diagnostic)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
      "targets": [{"expr": "katzenpost_replica_outgoing_queue_length", "refId": "A", "legendFormat": "{{job}} - {{peer}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 13,
      "title": "Replica: Retry Queue Size",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
      "targets": [{"expr": "katzenpost_replica_retry_queue_size", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 14,
      "title": "Replica: Retry Queue Drops (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
      "targets": [{"expr": "rate(katzenpost_replica_retry_queue_dropped_total[1m])", "refId": "A", "legendFormat": "{{job}} - {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 15,
      "title": "Replica: Incoming Real Reply Latency (p50/p90/p99)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 48},
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(katzenpost_replica_incoming_real_reply_latency_seconds_bucket[5m]))", "refId": "A", "legendFormat": "{{job}} p50"},
        {"expr": "histogram_quantile(0.90, rate(katzenpost_replica_incoming_real_reply_latency_seconds_bucket[5m]))", "refId": "B", "legendFormat": "{{job}} p90"},
        {"expr": "histogram_quantile(0.99, rate(katzenpost_replica_incoming_real_reply_latency_seconds_bucket[5m]))", "refId": "C", "legendFormat": "{{job}} p99"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 16,
      "title": "Replica: Incoming Decoy Reply Latency (p50/p90/p99)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 48},
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(katzenpost_replica_incoming_decoy_reply_latency_seconds_bucket[5m]))", "refId": "A", "legendFormat": "{{job}} p50"},
        {"expr": "histogram_quantile(0.90, rate(katzenpost_replica_incoming_decoy_reply_latency_seconds_bucket[5m]))", "refId": "B", "legendFormat": "{{job}} p90"},
        {"expr": "histogram_quantile(0.99, rate(katzenpost_replica_incoming_decoy_reply_latency_seconds_bucket[5m]))", "refId": "C", "legendFormat": "{{job}} p99"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 17,
      "title": "Replica: Replication Latency (p50/p90/p99)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 56},
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(katzenpost_replica_replication_latency_seconds_bucket[5m]))", "refId": "A", "legendFormat": "{{job}} p50"},
        {"expr": "histogram_quantile(0.90, rate(katzenpost_replica_replication_latency_seconds_bucket[5m]))", "refId": "B", "legendFormat": "{{job}} p90"},
        {"expr": "histogram_quantile(0.99, rate(katzenpost_replica_replication_latency_seconds_bucket[5m]))", "refId": "C", "legendFormat": "{{job}} p99"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 18,
      "title": "Courier: Enqueue Rate per Replica (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 64},
      "targets": [{"expr": "rate(katzenpost_courier_enqueue_total[1m])", "refId": "A", "legendFormat": "{{job}} -> {{replica}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 19,
      "title": "Courier: Oldest Pending Message Age per Replica",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 64},
      "targets": [{"expr": "katzenpost_courier_oldest_age_seconds", "refId": "A", "legendFormat": "{{job}} -> {{replica}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 20,
      "title": "Courier: Processing Duration p50/p90/p99 per Replica",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 72},
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(katzenpost_courier_processing_duration_seconds_bucket[5m]))", "refId": "A", "legendFormat": "{{job}} {{replica}} p50"},
        {"expr": "histogram_quantile(0.90, rate(katzenpost_courier_processing_duration_seconds_bucket[5m]))", "refId": "B", "legendFormat": "{{job}} {{replica}} p90"},
        {"expr": "histogram_quantile(0.99, rate(katzenpost_courier_processing_duration_seconds_bucket[5m]))", "refId": "C", "legendFormat": "{{job}} {{replica}} p99"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 21,
      "title": "Courier: Peer Connected per Replica (1=connected, 0=disconnected)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 80},
      "targets": [{"expr": "katzenpost_courier_peer_connected", "refId": "A", "legendFormat": "{{job}} -> {{replica}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short", "min": 0, "max": 1}, "overrides": []}
    },
    {
      "id": 22,
      "title": "Courier: Drops by Reason (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 80},
      "targets": [{"expr": "rate(katzenpost_courier_dropped_reason_total[1m])", "refId": "A", "legendFormat": "{{job}} {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 23,
      "title": "Replica: Drops by Reason (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 88},
      "targets": [{"expr": "rate(katzenpost_replica_dropped_reason_total[1m])", "refId": "A", "legendFormat": "{{job}} {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "description": "Per-replica drop attribution introduced in commit 294d3fc2. Reasons: nil_command (a connector dispatched a nil command, should never fire), malformed_rebalance_fingerprint (the persisted rebalance marker was corrupt on startup), peer_permanent_error (a peer replica returned a permanent ErrorCode during replication, retry is futile)."
    },
    {
      "id": 24,
      "title": "Courier: Outgoing Backpressure Indicator (queue length × oldest age)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 88},
      "targets": [{"expr": "katzenpost_courier_queue_length * katzenpost_courier_oldest_age_seconds", "refId": "A", "legendFormat": "{{job}} -> {{replica}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "description": "Composite indicator for the courier dispatch path's lack of an overflow bound (the third concern from the recent queue audit). Multiplying queue depth by oldest-pending age yields a number that grows linearly during a slow-replica stall and is exactly zero in steady state. A sustained non-zero value during the courier_backlog_recovery scenario would confirm the bound is needed."
    }
  ]
}
`)

	// Packet loss dashboard
	plFile := filepath.Join(dbDir, "mix-packet-loss.json")
	log.Printf(WritingLogFormat, plFile)
	pl, err := os.Create(plFile)
	if err != nil {
		return err
	}
	defer pl.Close()
	Write(pl, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Mix Network Packet Loss",
  "uid": "katzenpost-packet-loss",
  "version": 1,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "Packets Dropped (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "targets": [{"expr": "rate(katzenpost_dropped_packets_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 2,
      "title": "Deadline Blown Drops (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "targets": [{"expr": "rate(katzenpost_dropped_deadline_blown_packets_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 3,
      "title": "Invalid + Replayed Packets (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
      "targets": [
        {"expr": "rate(katzenpost_dropped_invalid_packets_total[1m])", "refId": "A", "legendFormat": "{{job}} invalid"},
        {"expr": "rate(katzenpost_replayed_packets_total[1m])", "refId": "B", "legendFormat": "{{job}} replayed"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 4,
      "title": "Outgoing Packets Dropped (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
      "targets": [{"expr": "rate(katzenpost_dropped_outgoing_packets_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 5,
      "title": "Mix Queue Size",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
      "targets": [{"expr": "rate(katzenpost_mix_queue_size_sum[1m]) / rate(katzenpost_mix_queue_size_count[1m])", "refId": "A", "legendFormat": "{{job}} avg"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 6,
      "title": "Ingress Queue Size",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
      "targets": [{"expr": "rate(katzenpost_ingress_queue_size_sum[1m]) / rate(katzenpost_ingress_queue_size_count[1m])", "refId": "A", "legendFormat": "{{job}} avg"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 7,
      "title": "Gateway Token-Bucket Drops (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
      "targets": [{"expr": "rate(katzenpost_dropped_rate_limit_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 8,
      "title": "Sphinx Unwraps (rate/s, realised throughput)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
      "targets": [{"expr": "rate(katzenpost_sphinx_unwraps_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 9,
      "title": "Mix Server Drops by Reason (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 10, "w": 12, "x": 0, "y": 32},
      "targets": [{"expr": "sum by (job, reason) (rate(katzenpost_dropped_reason_total[1m]))", "refId": "A", "legendFormat": "{{job}} {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops", "custom": {"stacking": {"mode": "normal"}}}, "overrides": []},
      "description": "Every per-reason drop site in server/internal/instrument. Use this panel to attribute the totals on panel 1 to specific code paths (unwrap_failed, scheduler_deadline_blown, kaetzchen_handler_failed, gateway_rate_limited, etc.). The kaetzchen_* reasons were added in commit 9ccaa106; the cbor_kaetzchen_* reasons too."
    },
    {
      "id": 10,
      "title": "Replica Drops by Reason (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 10, "w": 12, "x": 12, "y": 32},
      "targets": [{"expr": "sum by (job, reason) (rate(katzenpost_replica_dropped_reason_total[1m]))", "refId": "A", "legendFormat": "{{job}} {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops", "custom": {"stacking": {"mode": "normal"}}}, "overrides": []},
      "description": "Replica-side drop attribution introduced in commit 294d3fc2. Reasons include nil_command, malformed_rebalance_fingerprint, peer_permanent_error. Sister to the mix-server reason counter on panel 9; the replica's own retry-queue evictions are on the courier-replica dashboard."
    },
    {
      "id": 11,
      "title": "Courier Drops by Reason (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 10, "w": 12, "x": 0, "y": 42},
      "targets": [{"expr": "sum by (job, reason) (rate(katzenpost_courier_dropped_reason_total[1m]))", "refId": "A", "legendFormat": "{{job}} {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops", "custom": {"stacking": {"mode": "normal"}}}, "overrides": []},
      "description": "Courier-side drop attribution. Currently the only fired reason is send_command_failed (outgoing connection error), but the metric will sprout series as future drop sites are paired."
    },
    {
      "id": 12,
      "title": "All Drops by Reason — Cluster Total (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 10, "w": 12, "x": 12, "y": 42},
      "targets": [
        {"expr": "sum by (reason) (rate(katzenpost_dropped_reason_total[1m]))", "refId": "A", "legendFormat": "mix:{{reason}}"},
        {"expr": "sum by (reason) (rate(katzenpost_replica_dropped_reason_total[1m]))", "refId": "B", "legendFormat": "replica:{{reason}}"},
        {"expr": "sum by (reason) (rate(katzenpost_courier_dropped_reason_total[1m]))", "refId": "C", "legendFormat": "courier:{{reason}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops", "custom": {"stacking": {"mode": "normal"}}}, "overrides": []},
      "description": "Per-reason drop rate across the whole cluster, with the originating subsystem in the legend prefix. The single panel a chaos investigator should look at first when packet loss appears under chaos."
    }
  ]
}
`)

	// Server health dashboard: the remaining server-side counters that
	// neither the courier-replica nor the packet-loss dashboards cover.
	shFile := filepath.Join(dbDir, "server-health.json")
	log.Printf(WritingLogFormat, shFile)
	sh, err := os.Create(shFile)
	if err != nil {
		return err
	}
	defer sh.Close()
	Write(sh, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Katzenpost Server Health",
  "uid": "katzenpost-server-health",
  "version": 1,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "Incoming Requests (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "targets": [{"expr": "rate(katzenpost_incoming_requests_total[1m])", "refId": "A", "legendFormat": "{{job}} {{command}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 2,
      "title": "Outgoing Connections (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "targets": [{"expr": "rate(katzenpost_outgoing_connections_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 3,
      "title": "Cancelled Outgoing Connections (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
      "targets": [{"expr": "rate(katzenpost_cancelled_outgoing_connections_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 4,
      "title": "Documents Ignored (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
      "targets": [{"expr": "rate(katzenpost_documents_ignored_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 5,
      "title": "Channel Usage",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16},
      "targets": [{"expr": "katzenpost_channel_usage", "refId": "A", "legendFormat": "{{job}} {{channel_name}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 6,
      "title": "Kaetzchen Requests (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 0, "y": 24},
      "targets": [{"expr": "rate(katzenpost_kaetzchen_requests_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 7,
      "title": "Kaetzchen Drops (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 8, "y": 24},
      "targets": [
        {"expr": "rate(katzenpost_kaetzchen_dropped_packets_total[1m])", "refId": "A", "legendFormat": "{{job}} packets"},
        {"expr": "rate(katzenpost_kaetzchen_dropped_requests_total[1m])", "refId": "B", "legendFormat": "{{job}} requests"},
        {"expr": "rate(katzenpost_kaetzchen_mix_packets_dropped_total[1m])", "refId": "C", "legendFormat": "{{job}} mix-packets"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 8,
      "title": "Kaetzchen Failed (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 8, "x": 16, "y": 24},
      "targets": [{"expr": "rate(katzenpost_kaetzchen_failed_requests_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 9,
      "title": "Kaetzchen Request Duration (p50/p90/p99)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 32},
      "targets": [
        {"expr": "rate(katzenpost_kaetzchen_requests_duration_seconds_sum[5m]) / rate(katzenpost_kaetzchen_requests_duration_seconds_count[5m])", "refId": "A", "legendFormat": "{{job}} avg"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 10,
      "title": "PKI Documents per Epoch (totals)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
      "targets": [
        {"expr": "katzenpost_pki_docs_per_epoch_total", "refId": "A", "legendFormat": "{{job}} epoch {{epoch}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 11,
      "title": "PKI Fetches (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
      "targets": [
        {"expr": "rate(katzenpost_fetched_pki_docs_per_epoch_total[1m])", "refId": "A", "legendFormat": "{{job}} fetched"},
        {"expr": "rate(katzenpost_failed_fetch_pki_docs_per_epoch_total[1m])", "refId": "B", "legendFormat": "{{job}} failed"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 12,
      "title": "PKI Cache Errors (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 48},
      "targets": [
        {"expr": "rate(katzenpost_failed_pki_cache_generation_per_epoch_total[1m])", "refId": "A", "legendFormat": "{{job}} cache-gen"},
        {"expr": "rate(katzenpost_invalid_pki_cache_per_epoch_total[1m])", "refId": "B", "legendFormat": "{{job}} invalid-cache"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 13,
      "title": "PKI Fetch Duration (avg)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 48},
      "targets": [
        {"expr": "rate(katzenpost_fetched_pki_docs_per_epoch_duration_sum[5m]) / rate(katzenpost_fetched_pki_docs_per_epoch_duration_count[5m])", "refId": "A", "legendFormat": "{{job}} avg"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    }
  ]
}
`)

	// Handshake dashboard. PqXX is a five-message exchange: four
	// Noise messages plus a post-Noise NoOp that distinguishes
	// auth-success from auth-failure (see
	// core/wire/session.go:finalizeHandshake). The duration histogram
	// captures all five exchanges; the failure counter labels by
	// direction (incoming/outgoing) and the wire state at the point
	// of failure (including "finalization" for NoOp timeouts); the
	// two responder-side counters attribute boot-time PKI-propagation
	// races vs steady-state auth rejections.
	hsFile := filepath.Join(dbDir, "handshakes.json")
	log.Printf(WritingLogFormat, hsFile)
	hs, err := os.Create(hsFile)
	if err != nil {
		return err
	}
	defer hs.Close()
	Write(hs, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Katzenpost Handshakes",
  "uid": "katzenpost-handshakes",
  "version": 1,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "Handshake Duration p50 (success, by role+direction)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "targets": [
        {"expr": "histogram_quantile(0.5, sum by (job, direction, le) (rate(katzenpost_handshake_duration_seconds_bucket{result=\"success\"}[1m])))", "refId": "A", "legendFormat": "{{job}} {{direction}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 2,
      "title": "Handshake Duration p99 (success, by role+direction)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "targets": [
        {"expr": "histogram_quantile(0.99, sum by (job, direction, le) (rate(katzenpost_handshake_duration_seconds_bucket{result=\"success\"}[1m])))", "refId": "A", "legendFormat": "{{job}} {{direction}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 3,
      "title": "Handshake Failures by State (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
      "targets": [
        {"expr": "sum by (direction, state) (rate(katzenpost_handshake_failures_total[1m]))", "refId": "A", "legendFormat": "{{direction}} {{state}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 4,
      "title": "Failure Duration p99 (by direction)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
      "targets": [
        {"expr": "histogram_quantile(0.99, sum by (job, direction, le) (rate(katzenpost_handshake_duration_seconds_bucket{result=\"failure\"}[1m])))", "refId": "A", "legendFormat": "{{job}} {{direction}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 5,
      "title": "Responder Peer-Validation Failures (rate/s, by reason)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
      "targets": [
        {"expr": "sum by (reason) (rate(katzenpost_incoming_peer_validation_failures_total[1m]))", "refId": "A", "legendFormat": "{{reason}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 6,
      "title": "TCP Connections Refused: No PKI Doc (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24},
      "targets": [
        {"expr": "sum by (job) (rate(katzenpost_incoming_refused_no_pki_doc_total[1m]))", "refId": "A", "legendFormat": "{{job}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    }
  ]
}
`)

	// kpclientd dashboard: only meaningful when the daemon is built
	// with -tags kpclientd_metrics and scraped by prometheus. Emitted
	// unconditionally so that operators who later enable the build tag
	// find a ready-made dashboard.
	kcFile := filepath.Join(dbDir, "kpclientd.json")
	log.Printf(WritingLogFormat, kcFile)
	kc, err := os.Create(kcFile)
	if err != nil {
		return err
	}
	defer kc.Close()
	Write(kc, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Katzenpost kpclientd",
  "uid": "katzenpost-kpclientd",
  "version": 1,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "LambdaP: FIFO Pop (rate/s, real messages)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "targets": [{"expr": "rate(katzenpost_client_lambdap_fifo_pop_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 2,
      "title": "LambdaP: Decoy Fallback (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "targets": [{"expr": "rate(katzenpost_client_lambdap_decoy_total[1m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 3,
      "title": "LambdaP: Aggregate Emission Rate (real + decoy)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
      "targets": [{"expr": "rate(katzenpost_client_lambdap_fifo_pop_total[1m]) + rate(katzenpost_client_lambdap_decoy_total[1m])", "refId": "A", "legendFormat": "{{job}} observed LambdaP"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 4,
      "title": "LambdaL: Loop Decoy Rate",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
      "targets": [{"expr": "rate(katzenpost_client_lambdal_decoy_total[1m])", "refId": "A", "legendFormat": "{{job}} observed LambdaL"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 5,
      "title": "Send Queue Depth (aggregate)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
      "targets": [{"expr": "katzenpost_client_send_queue_depth", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 6,
      "title": "ARQ In-Flight",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
      "targets": [{"expr": "katzenpost_client_arq_inflight", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 7,
      "title": "Gateway Connected",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
      "targets": [{"expr": "katzenpost_client_gateway_connected", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short", "min": 0, "max": 1}, "overrides": []}
    },
    {
      "id": 8,
      "title": "PKI Document Age",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
      "targets": [{"expr": "katzenpost_client_pki_doc_age_seconds", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 9,
      "title": "ARQ Round-Trip Latency (p50/p90/p99)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(katzenpost_client_arq_round_trip_seconds_bucket[5m]))", "refId": "A", "legendFormat": "{{job}} p50"},
        {"expr": "histogram_quantile(0.90, rate(katzenpost_client_arq_round_trip_seconds_bucket[5m]))", "refId": "B", "legendFormat": "{{job}} p90"},
        {"expr": "histogram_quantile(0.99, rate(katzenpost_client_arq_round_trip_seconds_bucket[5m]))", "refId": "C", "legendFormat": "{{job}} p99"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    },
    {
      "id": 10,
      "title": "Thin Client Sessions (count)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
      "targets": [{"expr": "katzenpost_client_thin_sessions", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 11,
      "title": "SURB ID Lifecycle (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
      "targets": [
        {"expr": "rate(katzenpost_client_surb_id_created_total[1m])", "refId": "A", "legendFormat": "{{job}} created"},
        {"expr": "rate(katzenpost_client_surb_id_delivered_total[1m])", "refId": "B", "legendFormat": "{{job}} delivered (exit)"},
        {"expr": "rate(katzenpost_client_surb_id_rotated_total[1m])", "refId": "C", "legendFormat": "{{job}} rotated (exit)"},
        {"expr": "rate(katzenpost_client_surb_id_garbage_collected_total[1m])", "refId": "D", "legendFormat": "{{job}} gc'd (exit)"},
        {"expr": "rate(katzenpost_client_surb_id_reply_matched_total[1m])", "refId": "E", "legendFormat": "{{job}} reply_matched (NOT an exit)"},
        {"expr": "rate(katzenpost_client_surb_id_reply_no_match_total[1m])", "refId": "F", "legendFormat": "{{job}} reply_no_match (no entry)"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 12,
      "title": "SURB ID Reply-No-Match Total (diagnostic for reply routing)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 48},
      "targets": [{"expr": "katzenpost_client_surb_id_reply_no_match_total", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 13,
      "title": "SURB Lifecycle Balance: created vs exits (cumulative)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 56},
      "targets": [
        {"expr": "katzenpost_client_surb_id_created_total", "refId": "A", "legendFormat": "{{job}} created"},
        {"expr": "katzenpost_client_surb_id_delivered_total + katzenpost_client_surb_id_garbage_collected_total + katzenpost_client_surb_id_rotated_total", "refId": "B", "legendFormat": "{{job}} exits (delivered+gc+rotated)"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "description": "Lifecycle invariant. The two series should track each other closely; the gap is the sum of (currently in-flight ARQ entries) and (entries that exited via the still-uncounted error or cancel paths). A persistent widening with no in-flight growth indicates either a SURBID is being abandoned without firing any exit counter, or an error/cancel-exit site needs its own counter."
    },
    {
      "id": 14,
      "title": "SURB Lifecycle Gap (created minus counted exits)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 56},
      "targets": [
        {"expr": "katzenpost_client_surb_id_created_total - (katzenpost_client_surb_id_delivered_total + katzenpost_client_surb_id_garbage_collected_total + katzenpost_client_surb_id_rotated_total)", "refId": "A", "legendFormat": "{{job}} unaccounted"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []},
      "description": "Same as panel 13 but as a single signed series. Tracks arq_inflight + uncounted error/cancel exits under healthy operation; a value that grows without arq_inflight also growing and with no error/cancel activity indicates a real leak."
    }
  ]
}
`)

	// Dirauth dashboard. The voting directory authorities have no
	// in-band reporting of their consensus state today; this surface
	// fills the gap. Panels organised by FSM, vote and descriptor
	// flow, peer health, and document generation.
	daFile := filepath.Join(dbDir, "dirauth.json")
	log.Printf(WritingLogFormat, daFile)
	da, err := os.Create(daFile)
	if err != nil {
		return err
	}
	defer da.Close()
	Write(da, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Katzenpost Dirauth",
  "uid": "katzenpost-dirauth",
  "version": 1,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "Voting FSM Phase (0=bootstrap 1=desc 2=vote 3=reveal 4=cert 5=sig)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "targets": [{"expr": "katzenpost_dirauth_voting_phase", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short", "min": -1, "max": 5}, "overrides": []}
    },
    {
      "id": 2,
      "title": "Current Voting Epoch",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "targets": [{"expr": "katzenpost_dirauth_current_epoch", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}
    },
    {
      "id": 3,
      "title": "Votes Received (rate/s by result)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
      "targets": [{"expr": "rate(katzenpost_dirauth_votes_received_total[1m])", "refId": "A", "legendFormat": "{{job}} {{result}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 4,
      "title": "Descriptors Accepted (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
      "targets": [{"expr": "rate(katzenpost_dirauth_descriptors_accepted_total[1m])", "refId": "A", "legendFormat": "{{job}} {{kind}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 5,
      "title": "Descriptors Rejected (rate/s, stacked by reason)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
      "targets": [{"expr": "rate(katzenpost_dirauth_descriptors_rejected_total[1m])", "refId": "A", "legendFormat": "{{job}} {{kind}} {{reason}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 6,
      "title": "Consensus Reached (rate/s, should average 1 per epoch)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
      "targets": [{"expr": "rate(katzenpost_dirauth_consensus_reached_total[5m])", "refId": "A", "legendFormat": "{{job}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 7,
      "title": "Peer Send Result (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
      "targets": [{"expr": "rate(katzenpost_dirauth_peer_send_attempt_total[1m])", "refId": "A", "legendFormat": "{{job}} {{peer}} {{result}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []}
    },
    {
      "id": 8,
      "title": "Peer Connected (1=connected, 0=disconnected)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 32},
      "targets": [{"expr": "katzenpost_dirauth_peer_connected", "refId": "A", "legendFormat": "{{job}} -> {{peer}}"}],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short", "min": 0, "max": 1}, "overrides": []}
    },
    {
      "id": 9,
      "title": "Document Generation Latency (p50/p90/p99)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 32},
      "targets": [
        {"expr": "histogram_quantile(0.50, rate(katzenpost_dirauth_document_generation_seconds_bucket[5m]))", "refId": "A", "legendFormat": "{{job}} p50"},
        {"expr": "histogram_quantile(0.90, rate(katzenpost_dirauth_document_generation_seconds_bucket[5m]))", "refId": "B", "legendFormat": "{{job}} p90"},
        {"expr": "histogram_quantile(0.99, rate(katzenpost_dirauth_document_generation_seconds_bucket[5m]))", "refId": "C", "legendFormat": "{{job}} p99"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []}
    }
  ]
}
`)

	// SEDA-style load-curve dashboard. Driven by the chaos
	// parallel-load tool's prometheus surface; panels show
	// throughput-vs-load knees, response-time quantiles and CDF,
	// the Jain fairness index across thin clients, and the
	// downstream courier oldest-age and drop-by-reason signals.
	sedaFile := filepath.Join(dbDir, "seda-load.json")
	log.Printf(WritingLogFormat, sedaFile)
	sd, err := os.Create(sedaFile)
	if err != nil {
		return err
	}
	defer sd.Close()
	Write(sd, `{
  "annotations": {"list": []},
  "editable": true,
  "title": "Katzenpost SEDA Load Curves",
  "uid": "katzenpost-seda-load",
  "version": 1,
  "timezone": "browser",
  "refresh": "5s",
  "time": {"from": "now-30m", "to": "now"},
  "panels": [
    {
      "id": 1,
      "title": "Active Clients (offered concurrency)",
      "type": "timeseries",
      "gridPos": {"h": 6, "w": 12, "x": 0, "y": 0},
      "targets": [
        {"expr": "katzenpost_parallel_load_active_clients", "refId": "A", "legendFormat": "active"},
        {"expr": "katzenpost_parallel_load_sweep_step_clients", "refId": "B", "legendFormat": "sweep step"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short", "min": 0}, "overrides": []},
      "description": "Welsh figure 2 inspiration: track offered load to align the throughput and latency curves with the concurrency level."
    },
    {
      "id": 2,
      "title": "Successful Iteration Throughput (ops/s)",
      "type": "timeseries",
      "gridPos": {"h": 6, "w": 12, "x": 12, "y": 0},
      "targets": [
        {"expr": "sum(rate(katzenpost_parallel_load_iterations_total{result=\"ok\"}[30s]))", "refId": "A", "legendFormat": "total ok"},
        {"expr": "sum(rate(katzenpost_parallel_load_iterations_total{result=\"error\"}[30s]))", "refId": "B", "legendFormat": "total err"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "description": "Aggregate successful pigeonhole write+read cycles per second. The shape of this curve against the Active Clients gauge above is the saturation knee from SEDA figures 2 and 4."
    },
    {
      "id": 3,
      "title": "Iteration Latency Quantiles (s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 6},
      "targets": [
        {"expr": "histogram_quantile(0.50, sum by (le) (rate(katzenpost_parallel_load_iteration_seconds_bucket{op=\"cycle\"}[1m])))", "refId": "A", "legendFormat": "p50"},
        {"expr": "histogram_quantile(0.90, sum by (le) (rate(katzenpost_parallel_load_iteration_seconds_bucket{op=\"cycle\"}[1m])))", "refId": "B", "legendFormat": "p90"},
        {"expr": "histogram_quantile(0.99, sum by (le) (rate(katzenpost_parallel_load_iteration_seconds_bucket{op=\"cycle\"}[1m])))", "refId": "C", "legendFormat": "p99"},
        {"expr": "histogram_quantile(0.999, sum by (le) (rate(katzenpost_parallel_load_iteration_seconds_bucket{op=\"cycle\"}[1m])))", "refId": "D", "legendFormat": "p99.9"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
      "description": "SEDA figure 12b on a time axis. Watch the p99.9 line for the heavy tail that averages would hide."
    },
    {
      "id": 4,
      "title": "Iteration Latency CDF (probability that response_time <= bucket)",
      "type": "timeseries",
      "gridPos": {"h": 10, "w": 12, "x": 0, "y": 14},
      "targets": [
        {"expr": "sum by (le) (rate(katzenpost_parallel_load_iteration_seconds_bucket{op=\"cycle\"}[5m])) / on() group_left sum(rate(katzenpost_parallel_load_iteration_seconds_count{op=\"cycle\"}[5m]))", "refId": "A", "legendFormat": "<= {{le}}s"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "percentunit", "min": 0, "max": 1}, "overrides": []},
      "description": "Cumulative distribution of pigeonhole iteration latency, sampled over the last 5 minutes. The trailing series is the long tail."
    },
    {
      "id": 5,
      "title": "Jain Fairness Index across clients (1.0 = perfectly equal service)",
      "type": "timeseries",
      "gridPos": {"h": 10, "w": 12, "x": 12, "y": 14},
      "targets": [
        {"expr": "(sum(rate(katzenpost_parallel_load_iterations_total{result=\"ok\"}[1m])))^2 / (count(rate(katzenpost_parallel_load_iterations_total{result=\"ok\"}[1m])) * sum((rate(katzenpost_parallel_load_iterations_total{result=\"ok\"}[1m]))^2))", "refId": "A", "legendFormat": "Jain index"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "short", "min": 0, "max": 1.05}, "overrides": []},
      "description": "Jain (1984) fairness across thin clients. f(x) = (sum xi)^2 / (N * sum xi^2) where xi is per-client throughput. 1.0 means every client got equal service; a drop below 0.95 indicates scheduling or queueing unfairness somewhere in the daemon, gateway, courier, or replica path."
    },
    {
      "id": 6,
      "title": "Per-client iteration rate (ops/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24},
      "targets": [
        {"expr": "rate(katzenpost_parallel_load_iterations_total{result=\"ok\"}[1m])", "refId": "A", "legendFormat": "{{client_id}} ok"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "description": "Per-thin-client iteration rate. Visual companion to the Jain index above; spread is the unfairness."
    },
    {
      "id": 7,
      "title": "Errors by stage and kind (rate/s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 24, "x": 0, "y": 32},
      "targets": [
        {"expr": "rate(katzenpost_parallel_load_errors_total[1m])", "refId": "A", "legendFormat": "{{stage}} / {{kind}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "description": "Categorised iteration failures. ARQ-level outcomes like tombstone or box_not_found land here too; they are legitimate end states, not bugs."
    },
    {
      "id": 8,
      "title": "Courier oldest queue age vs offered load (s)",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 40},
      "targets": [
        {"expr": "katzenpost_courier_oldest_age_seconds", "refId": "A", "legendFormat": "{{job}} -> {{replica}}"},
        {"expr": "katzenpost_parallel_load_active_clients", "refId": "B", "legendFormat": "active clients"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "s"}, "overrides": []},
      "description": "Cross-pane: as the parallel-load tool ramps offered concurrency, watch the courier's oldest-age gauge climb. SEDA's queue-length plots (figure 8) are this gauge's analogue here."
    },
    {
      "id": 9,
      "title": "Courier drops by reason (rate/s) under offered load",
      "type": "timeseries",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 40},
      "targets": [
        {"expr": "sum by (reason) (rate(katzenpost_courier_dropped_reason_total[1m]))", "refId": "A", "legendFormat": "{{reason}}"}
      ],
      "datasource": "Prometheus",
      "fieldConfig": {"defaults": {"unit": "ops"}, "overrides": []},
      "description": "Categorical drop rates correlated with offered load. queue_full is the canonical backpressure signal."
    }
  ]
}
`)

	return nil
}

func (s *Katzenpost) GenDockerCompose(dockerImage string) error {
	dest := filepath.Join(s.OutDir, "docker-compose.yml")
	log.Printf(WritingLogFormat, dest)
	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	replicas, gateways, serviceNodes, mixes, err := s.GenAuthorizedNodes()

	if err != nil {
		log.Fatal(err)
	}

	// writeEnv emits the environment block for a service.
	writeEnv := func(serviceName string) {
		var envVars []string
		if s.EpochDuration != "" {
			envVars = append(envVars, fmt.Sprintf("KATZENPOST_EPOCH_DURATION=%s", s.EpochDuration))
		}
		if s.PyroscopeDirauth && strings.HasPrefix(serviceName, "auth") {
			envVars = append(envVars, "PYROSCOPE_SERVER_ADDRESS=http://pyroscope:4040")
			envVars = append(envVars, "PYROSCOPE_APP_NAME=katzenpost-dirauth")
			envVars = append(envVars, fmt.Sprintf("PYROSCOPE_SERVICE_TAG=%s", serviceName))
		}
		if s.PyroscopeKpclientd && serviceName == "kpclientd" {
			envVars = append(envVars, "PYROSCOPE_SERVER_ADDRESS=http://pyroscope:4040")
			envVars = append(envVars, "PYROSCOPE_APP_NAME=katzenpost-kpclientd")
			envVars = append(envVars, "PYROSCOPE_SERVICE_TAG=kpclientd")
		}
		if len(envVars) > 0 {
			Write(f, `
    environment:`)
			for _, v := range envVars {
				Write(f, `
      - %s`, v)
			}
		}
	}

	// writeKatzenpostService emits the common scaffolding for a service
	// built from the katzenpost base image: container_name and hostname
	// match the identifier so peers can address it as
	// `tcp://<name>:<port>` via the bridge's embedded DNS, the source
	// tree is mounted read-write for log persistence, and the service
	// joins the single katzenpost bridge network. The caller appends
	// depends_on/ports/environment as needed.
	writeKatzenpostService := func(name, command string) {
		Write(f, `
  %s:
    restart: "no"
    container_name: %s
    hostname: %s
    image: %s
    volumes:
      - ./:%s
    command: %s
    networks:
      - %s`, name, name, name, dockerImage, s.BaseDir, command, DockerNetwork)
	}

	writeDependsOnAuths := func() {
		Write(f, `
    depends_on:`)
		for _, authCfg := range s.VotingAuthConfigs {
			Write(f, `
      - %s`, authCfg.Server.Identifier)
		}
	}

	// Every service joins a single bridge network. With per-container
	// net namespaces, pumba can install `tc netem` qdiscs in each
	// service's namespace to model real network conditions between
	// hops; the previous host-networked layout had no such namespaces.
	Write(f, `
networks:
  %s:
    driver: bridge

services:
`, DockerNetwork)

	for _, p := range gateways {
		cmd := fmt.Sprintf("%s/server%s -f %s/%s/katzenpost.toml", s.BaseDir, s.BinSuffix, s.BaseDir, p.Identifier)
		writeKatzenpostService(p.Identifier, cmd)
		writeEnv(p.Identifier)
		writeDependsOnAuths()
	}

	for _, p := range serviceNodes {
		cmd := fmt.Sprintf("%s/server%s -f %s/%s/katzenpost.toml", s.BaseDir, s.BinSuffix, s.BaseDir, p.Identifier)
		writeKatzenpostService(p.Identifier, cmd)
		writeEnv(p.Identifier)
		writeDependsOnAuths()
	}

	for i := range mixes {
		name := fmt.Sprintf("mix%d", i+1)
		cmd := fmt.Sprintf("%s/server%s -f %s/%s/katzenpost.toml", s.BaseDir, s.BinSuffix, s.BaseDir, name)
		writeKatzenpostService(name, cmd)
		writeEnv(name)
		writeDependsOnAuths()
	}

	// pigeonhole storage replicas
	for i := range replicas {
		name := fmt.Sprintf("replica%d", i+1)
		cmd := fmt.Sprintf("%s/replica%s -f %s/%s/replica.toml", s.BaseDir, s.BinSuffix, s.BaseDir, name)
		writeKatzenpostService(name, cmd)
		writeEnv(name)
		writeDependsOnAuths()
	}

	for _, authCfg := range s.VotingAuthConfigs {
		name := authCfg.Server.Identifier
		cmd := fmt.Sprintf("%s/dirauth%s -f %s/%s/authority.toml", s.BaseDir, s.BinSuffix, s.BaseDir, name)
		writeKatzenpostService(name, cmd)
		writeEnv(name)
		Write(f, `
`)
	}

	if !s.NoMetrics {
		// Prometheus and grafana publish to host loopback so the operator
		// can browse them. Their scrape paths into the katzenpost
		// services run entirely on the bridge.
		Write(f, `
  metrics:
    restart: "no"
    container_name: metrics
    hostname: metrics
    image: docker.io/prom/prometheus
    pull_policy: if_not_present
    volumes:
      - ./:%s
    command: --config.file="%s/prometheus.yml"
    networks:
      - %s
    ports:
      - "127.0.0.1:9090:9090"
`, s.BaseDir, s.BaseDir, DockerNetwork)

		Write(f, `
  grafana:
    restart: "no"
    container_name: grafana
    hostname: grafana
    image: docker.io/grafana/grafana:latest
    pull_policy: if_not_present
    volumes:
      - ./grafana/provisioning/datasources:/etc/grafana/provisioning/datasources
      - ./grafana/provisioning/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
      - GF_FEATURE_TOGGLES_DISABLE=kubernetesDashboards
    networks:
      - %s
    ports:
      - "127.0.0.1:3000:3000"
    depends_on:
      - metrics
`, DockerNetwork)
	}

	if s.PyroscopeDirauth || s.PyroscopeKpclientd {
		Write(f, `
  pyroscope:
    restart: "no"
    container_name: pyroscope
    hostname: pyroscope
    image: docker.io/grafana/pyroscope:latest
    pull_policy: if_not_present
    networks:
      - %s
    ports:
      - "127.0.0.1:4040:4040"
`, DockerNetwork)
	}

	// kpclientd publishes its thin-client port (64331) on the host so
	// external thin clients (ping, fetch) running with --network=host
	// can dial 127.0.0.1:64331. Inside the bridge it is reachable as
	// kpclientd:64331 via compose DNS, which is how prometheus scrapes
	// it when kpclientd_metrics is enabled.
	cmd := fmt.Sprintf("%s/kpclientd%s -c %s/client/client.toml", s.BaseDir, s.BinSuffix, s.BaseDir)
	writeKatzenpostService("kpclientd", cmd)
	Write(f, `
    ports:
      - "127.0.0.1:64331:64331"`)
	writeEnv("kpclientd")
	Write(f, `
`)
	return nil
}
