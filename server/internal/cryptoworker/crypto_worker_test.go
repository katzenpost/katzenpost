package cryptoworker

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/sign"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/mixkeys"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/userdb"
)

type mockServer struct {
	cfg               *config.Config
	logBackend        *log.Backend
	identityKey       sign.PrivateKey
	identityPublicKey sign.PublicKey
	linkKey           kem.PrivateKey
	mixKeys           glue.MixKeys
	pki               glue.PKI
	gateway           glue.Gateway
	service           glue.ServiceNode
	scheduler         glue.Scheduler
	connector         glue.Connector
	listeners         []glue.Listener
}

type mockGlue struct {
	s     *mockServer
	decoy *mockDecoy
}

func (g *mockGlue) Config() *config.Config {
	return g.s.cfg
}

func (g *mockGlue) LogBackend() *log.Backend {
	return g.s.logBackend
}

func (g *mockGlue) IdentityKey() sign.PrivateKey {
	return g.s.identityKey
}

func (g *mockGlue) IdentityPublicKey() sign.PublicKey {
	return g.s.identityPublicKey
}

func (g *mockGlue) LinkKey() kem.PrivateKey {
	return g.s.linkKey
}

func (g *mockGlue) MixKeys() glue.MixKeys {
	return g.s.mixKeys
}

func (g *mockGlue) PKI() glue.PKI {
	return g.s.pki
}

func (g *mockGlue) Gateway() glue.Gateway {
	return g.s.gateway
}

func (g *mockGlue) ServiceNode() glue.ServiceNode {
	return g.s.service
}

func (g *mockGlue) Scheduler() glue.Scheduler {
	return g.s.scheduler
}

func (g *mockGlue) Connector() glue.Connector {
	return g.s.connector
}

func (g *mockGlue) Listeners() []glue.Listener {
	return g.s.listeners
}

func (g *mockGlue) ReshadowCryptoWorkers() {}

func (g *mockGlue) Decoy() glue.Decoy {
	return g.decoy
}

func (m *mockGlue) Management() *thwack.Server {
	return nil
}

type mockDecoy struct {
	count int
}

func (d *mockDecoy) Halt() {}

func (d *mockDecoy) ExpectReply(pkt *packet.Packet) bool {
	return false
}

func (d *mockDecoy) OnNewDocument(*pkicache.Entry) {}

func (d *mockDecoy) OnPacket(*packet.Packet) {}

func (d *mockDecoy) GetStats(doPublishEpoch uint64) *loops.LoopStats {
	return nil
}

type mockScheduler struct {
	count int
}

func (s *mockScheduler) Halt() {}

func (s *mockScheduler) OnNewMixMaxDelay(delay uint64) {}

func (s *mockScheduler) OnPacket(pkt *packet.Packet) {
	s.count++
}

type mockService struct {
	count int
}

func (s *mockService) Halt() {}

func (s *mockService) OnPacket(*packet.Packet) {
	s.count++
}

func (s *mockService) KaetzchenForPKI() (map[string]map[string]interface{}, error) {
	return nil, nil
}

type mockGateway struct {
	count int

	userName string
	userKey  kem.PublicKey
}

func (p *mockGateway) Halt() {}

func (p *mockGateway) UserDB() userdb.UserDB {
	return &mockUserDB{
		gateway: p,
	}
}

func (p *mockGateway) Spool() spool.Spool {
	return &mockSpool{}
}

func (p *mockGateway) AuthenticateClient(*wire.PeerCredentials) bool {
	return true
}

func (p *mockGateway) OnPacket(*packet.Packet) {
	p.count++
}

type mockUserDB struct {
	gateway *mockGateway
}

func (u *mockUserDB) Exists([]byte) bool {
	return true
}

func (u *mockUserDB) IsValid([]byte, kem.PublicKey) bool { return true }

func (u *mockUserDB) Add([]byte, kem.PublicKey, bool) error { return nil }

func (u *mockUserDB) SetIdentity([]byte, kem.PublicKey) error { return nil }

func (u *mockUserDB) Link([]byte) (kem.PublicKey, error) {
	return nil, nil
}

func (u *mockUserDB) Identity([]byte) (kem.PublicKey, error) {
	return u.gateway.userKey, nil
}

func (u *mockUserDB) Remove([]byte) error { return nil }

func (u *mockUserDB) Close() {}

type mockSpool struct{}

func (s *mockSpool) StoreMessage(u, msg []byte) error { return nil }

func (s *mockSpool) StoreSURBReply(u []byte, id *[constants.SURBIDLength]byte, msg []byte) error {
	return nil
}

func (s *mockSpool) Get(u []byte, advance bool) (msg, surbID []byte, remaining int, err error) {
	return []byte{1, 2, 3}, nil, 1, nil
}

func (s *mockSpool) Remove(u []byte) error { return nil }

func (s *mockSpool) VacuumExpired(udb userdb.UserDB, ignoreIdentities map[[32]byte]interface{}) error {
	return nil
}

func (s *mockSpool) Vacuum(udb userdb.UserDB) error { return nil }

func (s *mockSpool) Close() {}

func newTestGoo(t *testing.T) *mockGlue {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	goo := &mockGlue{
		decoy: new(mockDecoy),
		s: &mockServer{
			// cfg field is set in testRouting function below
			logBackend: logBackend,
			scheduler:  new(mockScheduler),
			gateway:    new(mockGateway),
			service:    new(mockService),
		},
	}
	return goo
}

// routing results
const (
	SentToDecoy = iota
	SentToGateway
	SentToService
	SentToScheduler
	Dropped
)

const (
	GatewayPacket = iota
	MixPacket
	ServicePacket
)

func routeResultToString(result int) string {
	switch result {
	case SentToDecoy:
		return "SentToDecoy"
	case SentToGateway:
		return "SentToGateway"
	case SentToService:
		return "SentToService"
	case SentToScheduler:
		return "SentToScheduler"
	case Dropped:
		return "Dropped"
	default:
		panic("wtf")
	}
}

func TestRoutePacket(t *testing.T) {
	nrHops := 5
	withSURB := true
	userForwardPayloadLength := 2000

	mygeo := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), userForwardPayloadLength, withSURB, nrHops)

	mixNodeConfig := &config.Config{
		SphinxGeometry: mygeo,
		Server: &config.Server{
			IsGatewayNode: false,
			IsServiceNode: false,
		},
		Logging: &config.Logging{},
		PKI:     &config.PKI{},
		Debug: &config.Debug{
			NumKaetzchenWorkers: 3,
			KaetzchenDelay:      300,
		},
	}

	serviceNodeConfig := &config.Config{
		SphinxGeometry: mygeo,
		Server: &config.Server{
			IsGatewayNode: false,
			IsServiceNode: true,
		},
		Logging: &config.Logging{},
		ServiceNode: &config.ServiceNode{
			Kaetzchen: []*config.Kaetzchen{
				&config.Kaetzchen{
					Capability: "echo",
					Endpoint:   "echo",
					Config:     map[string]interface{}{},
					Disable:    false,
				},
			},
		},
		PKI: &config.PKI{},
		Debug: &config.Debug{
			NumKaetzchenWorkers: 3,
			KaetzchenDelay:      300,
		},
	}

	gatewayNodeConfig := &config.Config{
		Gateway:        &config.Gateway{},
		SphinxGeometry: mygeo,
		Server: &config.Server{
			IsServiceNode: false,
			IsGatewayNode: true,
		},
		Logging: &config.Logging{},
		PKI:     &config.PKI{},
		Debug: &config.Debug{
			NumKaetzchenWorkers: 3,
			KaetzchenDelay:      300,
		},
	}

	/* table driven tests for the win!
	 */

	testCases := []struct {
		name          string
		nodeCfg       *config.Config
		packetType    int
		routingResult int
	}{
		// test cases for Gateway Node's routing logic:
		{
			name:          "gw_gwpacket",
			nodeCfg:       gatewayNodeConfig,
			packetType:    GatewayPacket,
			routingResult: SentToScheduler,
		},
		{
			name:          "gw_mixpacket",
			nodeCfg:       gatewayNodeConfig,
			packetType:    MixPacket,
			routingResult: SentToScheduler,
		},
		{
			name:          "gw_srvpacket",
			nodeCfg:       gatewayNodeConfig,
			packetType:    ServicePacket,
			routingResult: SentToGateway,
		},

		// test cases for Mix Node's routing logic:
		{
			name:          "mix_gwpacket",
			nodeCfg:       mixNodeConfig,
			packetType:    GatewayPacket,
			routingResult: SentToScheduler,
		},
		{
			name:          "mix_mixpacket",
			nodeCfg:       mixNodeConfig,
			packetType:    MixPacket,
			routingResult: SentToScheduler,
		},
		{
			name:          "mix_srvpacket",
			nodeCfg:       mixNodeConfig,
			packetType:    ServicePacket,
			routingResult: Dropped,
		},

		// test cases for Service Node's routing logic:
		{
			name:          "srv_gwpacket",
			nodeCfg:       serviceNodeConfig,
			packetType:    GatewayPacket,
			routingResult: SentToScheduler,
		},
		{
			name:          "srv_mixpacket",
			nodeCfg:       serviceNodeConfig,
			packetType:    MixPacket,
			routingResult: SentToScheduler,
		},
		{
			name:          "srv_srvpacket",
			nodeCfg:       serviceNodeConfig,
			packetType:    ServicePacket,
			routingResult: SentToService,
		},
	}

	for i := 0; i < len(testCases); i++ {
		result := testRouting(t, testCases[i].nodeCfg, testCases[i].packetType)
		routingResult := routeResultToString(result)
		t.Logf("test case %s returns %s", testCases[i].name, routingResult)

		require.Equal(t, testCases[i].routingResult, result)
	}
}

func createTestPacket(t *testing.T, nodePubKey nike.PublicKey, isMixNode, isGatewayNode, isServiceNode bool, mygeo *geo.Geometry) []byte {
	nodes, path := createTestRoute(t, mygeo, nodePubKey, isMixNode, isGatewayNode, isServiceNode)

	payload := make([]byte, mygeo.ForwardPayloadLength)
	payload[32] = 0x0a
	payload[33] = 0x0b

	mysphinx, err := sphinx.FromGeometry(mygeo)
	require.NoError(t, err)

	pkt, err := mysphinx.NewPacket(rand.Reader, path, payload)
	require.NoError(t, err)

	for i := 0; i < len(nodes); i++ {
		if nodes[i].privateKey == nil {
			break
		}
		b, _, cmds, err := mysphinx.Unwrap(nodes[i].privateKey, pkt)
		require.NoError(t, err)

		if i == len(path)-1 {
			require.Equal(t, 1, len(cmds))
			require.EqualValues(t, path[i].Commands[0], cmds[0])
			require.Equal(t, b, payload)
		} else {
			require.Equal(t, mysphinx.Geometry().PacketLength, len(pkt))
			require.Equal(t, 2, len(cmds))
			require.EqualValues(t, path[i].Commands[0], cmds[0])

			nextNode, ok := cmds[1].(*commands.NextNodeHop)
			require.True(t, ok)
			require.Equal(t, path[i+1].ID, nextNode.ID)
			require.Nil(t, b)
		}
	}
	return pkt
}

type nodeParams struct {
	id         [constants.NodeIDLength]byte
	privateKey nike.PrivateKey
	publicKey  nike.PublicKey
}

func newNikeNode(t *testing.T, mynike nike.Scheme) *nodeParams {
	n := new(nodeParams)
	_, err := rand.Read(n.id[:])
	require.NoError(t, err)
	n.publicKey, n.privateKey, err = mynike.GenerateKeyPair()
	require.NoError(t, err)
	return n
}

func createTestRoute(t *testing.T, geo *geo.Geometry, nodePubKey nike.PublicKey, isMixNode bool, isGatewayNode bool, isServiceNode bool) ([]*nodeParams, []*sphinx.PathHop) {
	isSURB := true
	delayBase := uint32(1000)

	// Generate the keypairs and node identifiers for the "nodes", except the one we pass in.
	nodes := make([]*nodeParams, geo.NrHops-1)
	mynike := schemes.ByName(geo.NIKEName)
	require.NotNil(t, mynike)

	for i := 0; i < len(nodes); i++ {
		nodes[i] = newNikeNode(t, mynike)
	}

	// Our test node, `myTestNode` is the only node in our slice of nodes whose `privateKey` field is nil;
	// this is simply because we don't need it and we cannot easily retrieve it without modifying code.
	myTestNode := new(nodeParams)
	myTestNode.publicKey = nodePubKey
	_, err := rand.Read(myTestNode.id[:])
	require.NoError(t, err)

	switch {
	case isMixNode == true:
		slice := []*nodeParams{}
		slice = append(slice, nodes[0])
		slice = append(slice, myTestNode)
		slice = append(slice, nodes[1:]...)
		nodes = slice
	case isGatewayNode == true:
		slice := []*nodeParams{}
		slice = append(slice, myTestNode)
		slice = append(slice, nodes...)
		nodes = slice
	case isServiceNode == true:
		slice := []*nodeParams{}
		slice = append(slice, nodes...)
		slice = append(slice, myTestNode)
		nodes = slice
	default:
		panic("creaTestRoute: invalid arguments")
	}

	if len(nodes) != geo.NrHops {
		panic("nodes must be NrNops in length")
	}

	// Assemble the path vector.
	path := make([]*sphinx.PathHop, geo.NrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].NIKEPublicKey = nodes[i].publicKey
		if i < geo.NrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase + uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Read(recipient.ID[:])
			require.NoError(t, err)
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Read(surbReply.ID[:])
				require.NoError(t, err)
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path
}

func testRouting(t *testing.T, nodeCfg *config.Config, packetType int) int {

	goo := newTestGoo(t)
	goo.s.cfg = nodeCfg

	testNodeMixkeys, err := mixkeys.NewMixKeys(goo, nodeCfg.SphinxGeometry)
	require.NoError(t, err)
	goo.s.mixKeys = testNodeMixkeys

	epoch, _, _ := epochtime.Now()
	mixkeyblob, ok := testNodeMixkeys.Get(epoch)
	require.True(t, ok)

	nikeScheme := schemes.ByName(nodeCfg.SphinxGeometry.NIKEName)
	nodePubKey, err := nikeScheme.UnmarshalBinaryPublicKey(mixkeyblob)
	require.NoError(t, err)

	var rawPacket []byte
	switch packetType {
	case GatewayPacket:
		rawPacket = createTestPacket(t, nodePubKey, false, true, false, nodeCfg.SphinxGeometry)
	case MixPacket:
		rawPacket = createTestPacket(t, nodePubKey, true, false, false, nodeCfg.SphinxGeometry)
	case ServicePacket:
		rawPacket = createTestPacket(t, nodePubKey, false, false, true, nodeCfg.SphinxGeometry)

	default:
		panic("invalid packet type")
	}

	incomingCh := make(chan interface{})
	cryptoworker := New(goo, incomingCh, 123)

	pkt, err := packet.New(rawPacket, nodeCfg.SphinxGeometry)
	require.NoError(t, err)

	err = cryptoworker.doUnwrap(pkt)
	require.NoError(t, err)

	startAt := time.Now()
	cryptoworker.routePacket(pkt, startAt)

	switch {
	case goo.s.scheduler.(*mockScheduler).count == 1:
		return SentToScheduler
	case goo.decoy.count == 1:
		return SentToDecoy
	case goo.s.gateway.(*mockGateway).count == 1:
		return SentToGateway
	case goo.s.service.(*mockService).count == 1:
		return SentToService
	default:
		return Dropped
	}

	// unreachable
}
