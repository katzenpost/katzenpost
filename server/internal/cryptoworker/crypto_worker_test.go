package cryptoworker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/katzenpost/katzenpost/server/internal/glue/gluefakes"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/packet"
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
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	nrHops := 5
	withSURB := true
	userForwardPayloadLength := 2000
	mygeo := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), userForwardPayloadLength, withSURB, nrHops)

	testCases := []struct {
		name           string
		configModifier func(*config.Config)
		isMixNode      bool
		isGatewayNode  bool
		isServiceNode  bool
		isSURB         bool
		expectFunction func(*gluefakes.FakeScheduler, *gluefakes.FakeGateway, *gluefakes.FakeServiceNode, *gluefakes.FakeDecoy)
	}{
		{
			name: "Gateway node routing to scheduler",
			configModifier: func(cfg *config.Config) {
				cfg.Server.IsGatewayNode = true
				cfg.Server.IsServiceNode = false
			},
			isMixNode:     false,
			isGatewayNode: true,
			isServiceNode: false,
			isSURB:        false,
			expectFunction: func(s *gluefakes.FakeScheduler, g *gluefakes.FakeGateway, sn *gluefakes.FakeServiceNode, d *gluefakes.FakeDecoy) {
				require.Equal(t, 1, s.OnPacketCallCount(), "Packet should be routed to the scheduler")
			},
		},
		{
			name: "Service node handling recipient packet",
			configModifier: func(cfg *config.Config) {
				cfg.Server.IsGatewayNode = false
				cfg.Server.IsServiceNode = true
			},
			isMixNode:     false,
			isGatewayNode: false,
			isServiceNode: true,
			isSURB:        false,
			expectFunction: func(s *gluefakes.FakeScheduler, g *gluefakes.FakeGateway, sn *gluefakes.FakeServiceNode, d *gluefakes.FakeDecoy) {
				require.Equal(t, 1, sn.OnPacketCallCount(), "Packet should be routed to the service node")
			},
		},
		{
			name: "Decoy node receiving SURB-Reply",
			configModifier: func(cfg *config.Config) {
				cfg.Server.IsGatewayNode = false
				cfg.Server.IsServiceNode = false
			},
			isMixNode:     true,
			isGatewayNode: false,
			isServiceNode: false,
			isSURB:        true,
			expectFunction: func(s *gluefakes.FakeScheduler, g *gluefakes.FakeGateway, sn *gluefakes.FakeServiceNode, d *gluefakes.FakeDecoy) {
				require.Equal(t, 1, d.OnPacketCallCount(), "Packet should be routed to the decoy node")
			},
		},
		{
			name: "Gateway node handling SURB-Reply directly",
			configModifier: func(cfg *config.Config) {
				cfg.Server.IsGatewayNode = true
				cfg.Server.IsServiceNode = false
			},
			isMixNode:     false,
			isGatewayNode: true,
			isServiceNode: false,
			isSURB:        true,
			expectFunction: func(s *gluefakes.FakeScheduler, g *gluefakes.FakeGateway, sn *gluefakes.FakeServiceNode, d *gluefakes.FakeDecoy) {
				require.Equal(t, 1, g.OnPacketCallCount(), "Packet should be handled directly by the gateway node")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
				Server:         &config.Server{},
				Logging:        &config.Logging{},
				PKI:            &config.PKI{},
				Debug: &config.Debug{
					NumKaetzchenWorkers: 3,
					KaetzchenDelay:      300,
				},
			}
			tc.configModifier(nodeCfg)
			fakeGlue.ConfigReturns(nodeCfg)

			mixkeyblob := make([]byte, 32)
			rand.Read(mixkeyblob)
			fakeMixKeys.GetReturns(mixkeyblob, true)
			nikeScheme := schemes.ByName("x25519")
			nodePubKey, err := nikeScheme.UnmarshalBinaryPublicKey(mixkeyblob)
			require.NoError(t, err)

			rawPacket, err := createTestPacket(nodePubKey, tc.isMixNode, tc.isGatewayNode, tc.isServiceNode, tc.isSURB, mygeo)
			require.NoError(t, err)

			pkt, err := packet.New(rawPacket, mygeo)
			require.NoError(t, err)

			incomingCh := make(chan interface{})
			cryptoWorker := New(fakeGlue, incomingCh, 123)
			cryptoWorker.routePacket(pkt, time.Now())

			tc.expectFunction(fakeScheduler, fakeGateway, fakeServiceNode, fakeDecoy)
		})
	}
}
