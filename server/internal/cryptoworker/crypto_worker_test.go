package cryptoworker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue/gluefakes"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

// routing results
const (
	SentToDecoy = iota
	SentToGateway
	SentToService
	SentToScheduler
	Dropped
)

const (
	NextHopPacket = iota
	RecipientPacket
	SURBReplyPacket
	SURBReplyDecoyPacket
)

func createTestPacket(nodePubKey nike.PublicKey, isMixNode, isGatewayNode, isServiceNode bool, isSURB bool, mygeo *geo.Geometry) ([]byte, error) {
	nodes, path, err := createTestRoute(mygeo, nodePubKey, isMixNode, isGatewayNode, isServiceNode, isSURB)
	if err != nil {
		return nil, fmt.Errorf("createTestRoute failed: %v", err)
	}

	payload := make([]byte, mygeo.ForwardPayloadLength)
	payload[32] = 0x0a
	payload[33] = 0x0b

	mysphinx, err := sphinx.FromGeometry(mygeo)

	pkt, err := mysphinx.NewPacket(rand.Reader, path, payload)
	if err != nil {
		return nil, fmt.Errorf("NewPacket failed: %v", err)
	}

	for i := 0; i < len(nodes); i++ {
		if nodes[i].privateKey == nil {
			break
		}
		b, _, cmds, err := mysphinx.Unwrap(nodes[i].privateKey, pkt)
		if err != nil {
			return nil, fmt.Errorf("unwrap failed: %v", err)
		}

		if i == len(path)-1 {
			if len(cmds) != 1 {
				return nil, fmt.Errorf("expected 1 command, got %d", len(cmds))
			}
			if !assert.ObjectsAreEqualValues(path[i].Commands[0], cmds[0]) {
				return nil, fmt.Errorf("cmds[0] expected %v, got %v", path[i].Commands[0], cmds[0])
			}
			if !assert.ObjectsAreEqualValues(b, payload) {
				return nil, fmt.Errorf("payload expected %v, got %v", b, payload)
			}

		} else {
			if mysphinx.Geometry().PacketLength != len(pkt) {
				return nil, fmt.Errorf("PacketLength expected %d, got %d", mysphinx.Geometry().PacketLength, len(pkt))
			}
			if 2 != len(cmds) {
				return nil, fmt.Errorf("expected 2 commands, got %d", len(cmds))
			}
			if !assert.ObjectsAreEqualValues(path[i].Commands[0], cmds[0]) {
				return nil, fmt.Errorf("cmds[0] expected %v, got %v", path[i].Commands[0], cmds[0])
			}

			nextNode, ok := cmds[1].(*commands.NextNodeHop)
			if !ok {
				return nil, fmt.Errorf("expected nextNodeHop, got %T", cmds[1])
			}
			if !assert.ObjectsAreEqualValues(path[i+1].ID, nextNode.ID) {
				return nil, fmt.Errorf("nextNodeHop.ID expected %v, got %v", path[i+1].ID, nextNode.ID)
			}
			if b != nil {
				return nil, fmt.Errorf("expected nil, got %v", b)
			}
		}
	}
	return pkt, nil
}

type nodeParams struct {
	id         [constants.NodeIDLength]byte
	privateKey nike.PrivateKey
	publicKey  nike.PublicKey
}

func newNikeNode(mynike nike.Scheme) (*nodeParams, error) {
	n := new(nodeParams)
	_, err := rand.Read(n.id[:])
	if err != nil {
		return nil, err
	}

	n.publicKey, n.privateKey, err = mynike.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return n, nil
}

func createTestRoute(geo *geo.Geometry, nodePubKey nike.PublicKey, isMixNode bool, isGatewayNode bool, isServiceNode bool, isSURB bool) ([]*nodeParams, []*sphinx.PathHop, error) {
	delayBase := uint32(1000)

	// Generate the keypairs and node identifiers for the "nodes", except the one we pass in.
	nodes := make([]*nodeParams, geo.NrHops-1)
	mynike := schemes.ByName(geo.NIKEName)
	if mynike == nil {
		return nil, nil, errors.New("createTestRoute: unknown nike scheme")
	}

	var err error
	for i := 0; i < len(nodes); i++ {
		nodes[i], err = newNikeNode(mynike)
		if err != nil {
			return nil, nil, err
		}
	}

	// Our test node, `myTestNode` is the only node in our slice of nodes whose `privateKey` field is nil;
	// this is simply because we don't need it and we cannot easily retrieve it without modifying code.
	myTestNode := new(nodeParams)
	myTestNode.publicKey = nodePubKey
	_, err = rand.Read(myTestNode.id[:])
	if err != nil {
		return nil, nil, err
	}

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
			_, err = rand.Read(recipient.ID[:])
			if err != nil {
				return nil, nil, err
			}
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Read(surbReply.ID[:])
				if err != nil {
					return nil, nil, err
				}
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path, nil
}

func TestRoutePacket(t *testing.T) {
	// Test environment setup
	logBackend, _ := log.New("", "DEBUG", false)
	nrHops := 5
	withSURB := true
	userForwardPayloadLength := 2000
	mygeo := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), userForwardPayloadLength, withSURB, nrHops)

	// Test cases with specific node configurations and routing outcomes
	testCases := []struct {
		name          string
		serverCfg     *config.Server
		packetType    int
		routingResult int
	}{
		// Gateway node's routing logic
		{"gw_nextHop", &config.Server{IsGatewayNode: true}, NextHopPacket, SentToScheduler},
		{"gw_recipient", &config.Server{IsGatewayNode: true}, RecipientPacket, SentToGateway},
		{"gw_SURBReply", &config.Server{IsGatewayNode: true}, SURBReplyPacket, SentToGateway},
		{"gw_SURBDecoyReply", &config.Server{IsGatewayNode: true}, SURBReplyDecoyPacket, SentToDecoy},

		// Mix node's routing logic
		{"mix_nextHop", &config.Server{}, NextHopPacket, SentToScheduler},
		{"mix_recipient", &config.Server{}, RecipientPacket, Dropped},
		{"mix_SURBReply", &config.Server{}, SURBReplyPacket, Dropped},
		{"mix_SURBDecoyReply", &config.Server{}, SURBReplyDecoyPacket, SentToDecoy},

		// Service node's routing logic
		{"srv_nextHop", &config.Server{IsServiceNode: true}, NextHopPacket, SentToScheduler},
		{"srv_recipient", &config.Server{IsServiceNode: true}, RecipientPacket, SentToService},
		{"srv_SURBReply", &config.Server{IsServiceNode: true}, SURBReplyPacket, SentToService},
		{"srv_SURBDecoyReply", &config.Server{IsServiceNode: true}, SURBReplyDecoyPacket, SentToDecoy},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock setup
			fakeGlue := new(gluefakes.FakeGlue)
			fakeScheduler := new(gluefakes.FakeScheduler)
			fakeGateway := new(gluefakes.FakeGateway)
			fakeMixKeys := new(gluefakes.FakeMixKeys)
			fakeServiceNode := new(gluefakes.FakeServiceNode)
			fakeDecoy := new(gluefakes.FakeDecoy)

			fakeGlue.LogBackendReturns(logBackend)
			fakeGlue.SchedulerReturns(fakeScheduler)
			fakeGlue.GatewayReturns(fakeGateway)
			fakeGlue.MixKeysReturns(fakeMixKeys)
			fakeGlue.ServiceNodeReturns(fakeServiceNode)
			fakeGlue.DecoyReturns(fakeDecoy)

			nodeCfg := &config.Config{
				Gateway:        &config.Gateway{},
				SphinxGeometry: mygeo,
				Server:         tc.serverCfg,
				Logging:        &config.Logging{},
				PKI:            &config.PKI{},
				Debug:          &config.Debug{},
			}

			fakeGlue.ConfigReturns(nodeCfg)

			mixkeyblob := make([]byte, 32)
			rand.Read(mixkeyblob)
			fakeMixKeys.GetReturns(mixkeyblob, true)
			nikeScheme := schemes.ByName("x25519")
			nodePubKey, err := nikeScheme.UnmarshalBinaryPublicKey(mixkeyblob)
			require.NoError(t, err)

			var rawPacket []byte
			//isDecoy := false

			switch tc.packetType {
			case NextHopPacket:
				rawPacket, err = createTestPacket(nodePubKey, false, true, false, false, nodeCfg.SphinxGeometry)
				// either of these works for creating a sphinx packet with a next hop command in it
				//rawPacket = createTestPacket(t, nodePubKey, true, false, false, false, nodeCfg.SphinxGeometry)
			case RecipientPacket:
				rawPacket, err = createTestPacket(nodePubKey, false, false, true, false, nodeCfg.SphinxGeometry)
			case SURBReplyPacket:
				rawPacket, err = createTestPacket(nodePubKey, false, false, true, true, nodeCfg.SphinxGeometry)
			case SURBReplyDecoyPacket:
				rawPacket, err = createTestPacket(nodePubKey, false, false, true, true, nodeCfg.SphinxGeometry)
				//isDecoy = true
			default:
				t.Fatalf("invalid packet type")
			}

			require.NoError(t, err)

			pkt, err := packet.New(rawPacket, mygeo)
			require.NoError(t, err)

			incomingCh := make(chan interface{})
			cryptoWorker := New(fakeGlue, incomingCh, 123)
			cryptoWorker.routePacket(pkt, time.Now())

			// Verify routing logic
			fakeSchedulerOnPacketCallCount := 0
			fakeGatewayOnPacketCallCount := 0
			fakeServiceNodeOnPacketCallCount := 0
			fakeDecoyOnPacketCallCount := 0

			switch tc.routingResult {
			case SentToScheduler:
				fakeSchedulerOnPacketCallCount = 1
			case SentToGateway:
				fakeGatewayOnPacketCallCount = 1
			case SentToService:
				fakeServiceNodeOnPacketCallCount = 1
			case SentToDecoy:
				fakeDecoyOnPacketCallCount = 1
			}

			assert.Equal(t, fakeSchedulerOnPacketCallCount, fakeScheduler.OnPacketCallCount())
			assert.Equal(t, fakeGatewayOnPacketCallCount, fakeGateway.OnPacketCallCount())
			assert.Equal(t, fakeServiceNodeOnPacketCallCount, fakeServiceNode.OnPacketCallCount())
			assert.Equal(t, fakeDecoyOnPacketCallCount, fakeDecoy.OnPacketCallCount())
		})
	}
}
