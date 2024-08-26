// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-or-later

package sphinx

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

func TestDisplaySphinxGeometries(t *testing.T) {
	tests := []struct {
		name        string
		isNIKE      bool
		nikeName    string
		kemName     string
		payloadSize int
		nrHops      int
	}{
		// NIKEs
		{
			name:        "X25519 NIKE",
			isNIKE:      true,
			nikeName:    "x25519",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "X448 NIKE",
			isNIKE:      true,
			nikeName:    "x448",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "CTIDH512-X25519 PQ Hybrid NIKE",
			isNIKE:      true,
			nikeName:    "CTIDH512-X25519",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},

		// NIKEs adapted as KEMs (via adhoc hashed elgamal construction)
		{
			name:        "X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x25519",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "X448 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x448",
			nrHops:      5,
			payloadSize: 2000,
		},

		// more KEMs
		{
			name:        "Xwing KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "Xwing",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "MLKEM768-X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "MLKEM768-X25519",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "MLKEM768-X448 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "MLKEM768-X448",
			nrHops:      5,
			payloadSize: 2000,
		},
	}

	for i := 0; i < len(tests); i++ {
		t.Run(tests[i].name, func(t *testing.T) {
			if tests[i].isNIKE {
				scheme := nikeSchemes.ByName(tests[i].nikeName)
				g := geo.GeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, tests[i].nrHops)
				t.Logf("HeaderLength: %d, PacketLength: %d", g.HeaderLength, g.PacketLength)
			} else { // KEM
				scheme := kemSchemes.ByName(tests[i].kemName)
				g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, tests[i].nrHops)
				t.Logf("HeaderLength: %d, PacketLength: %d", g.HeaderLength, g.PacketLength)
			}
		})
	}
}

func TestDisplaySphinxGeometryRanges(t *testing.T) {
	tests := []struct {
		name        string
		isNIKE      bool
		nikeName    string
		kemName     string
		payloadSize int
		startHop    int
		endHop      int
	}{
		// NIKEs
		{
			name:        "X25519 NIKE",
			isNIKE:      true,
			nikeName:    "x25519",
			kemName:     "",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "X448 NIKE",
			isNIKE:      true,
			nikeName:    "x448",
			kemName:     "",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "CTIDH512-X25519 PQ Hybrid NIKE",
			isNIKE:      true,
			nikeName:    "CTIDH512-X25519",
			kemName:     "",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},

		// NIKEs adapted as KEMs (via adhoc hashed elgamal construction)
		{
			name:        "X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x25519",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "X448 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x448",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},

		// more KEMs
		{
			name:        "Xwing KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "Xwing",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "MLKEM768-X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "MLKEM768-X25519",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "MLKEM768-X448 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "MLKEM768-X448",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
	}

	for i := 0; i < len(tests); i++ {
		t.Run(tests[i].name, func(t *testing.T) {
			if tests[i].isNIKE {
				for j := tests[i].startHop; j < tests[i].endHop+1; j++ {
					scheme := nikeSchemes.ByName(tests[i].nikeName)
					g := geo.GeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, j)
					t.Logf("Hops: %d, HeaderLength: %d, PacketLength: %d", j, g.HeaderLength, g.PacketLength)
				}
			} else { // KEM
				for j := tests[i].startHop; j < tests[i].endHop+1; j++ {
					scheme := kemSchemes.ByName(tests[i].kemName)
					g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, j)
					t.Logf("Hops: %d, HeaderLength: %d, PacketLength: %d", j, g.HeaderLength, g.PacketLength)
				}
			}
		})
	}
}

func TestSphinx(t *testing.T) {
	tests := []struct {
		name      string
		isNIKE    bool
		nikeName  string
		kemName   string
		startHop  int
		endHop    int
		isForward bool
	}{
		// NIKEs
		{
			name:      "X25519 NIKE forward",
			isNIKE:    true,
			nikeName:  "x25519",
			kemName:   "",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},
		{
			name:      "X25519 NIKE SURB reply",
			isNIKE:    true,
			nikeName:  "x25519",
			kemName:   "",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},
		{
			name:      "X448 NIKE forward",
			isNIKE:    true,
			nikeName:  "x448",
			kemName:   "",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},
		{
			name:      "X448 NIKE SURB reply",
			isNIKE:    true,
			nikeName:  "x448",
			kemName:   "",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},

		/* NOTE(david): test case disabled because it's too damn slow
		{
			name:     "CTIDH512-X25519 PQ Hybrid NIKE",
			isNIKE:   true,
			nikeName: "CTIDH512-X25519",
			kemName:  "",
			startHop: 5,
			endHop:   5,
		},
		*/

		// NIKEs adapted as KEMs (via adhoc hashed elgamal construction)
		{
			name:      "X25519 KEM forward",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "x25519",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},
		{
			name:      "X25519 KEM SURB reply",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "x25519",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},
		{
			name:      "X448 KEM forward",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "x448",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},
		{
			name:      "X448 KEM SURB reply",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "x448",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},

		// more KEMs
		{
			name:      "Xwing KEM forward",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "Xwing",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},
		{
			name:      "Xwing KEM SURB reply",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "Xwing",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},
		{
			name:      "MLKEM768-X25519 KEM forward",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "MLKEM768-X25519",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},
		{
			name:      "MLKEM768-X25519 KEM SURB reply",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "MLKEM768-X25519",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},
		{
			name:      "MLKEM768-X448 KEM forward",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "MLKEM768-X448",
			startHop:  5,
			endHop:    7,
			isForward: true,
		},
		{
			name:      "MLKEM768-X448 KEM SURB reply",
			isNIKE:    false,
			nikeName:  "",
			kemName:   "MLKEM768-X448",
			startHop:  5,
			endHop:    7,
			isForward: false,
		},
	}

	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."
	payloadSize := 2000
	payload := make([]byte, payloadSize)
	copy(payload[:len(testPayload)], testPayload) // some kind of payload that is not all zero bytes

	for i := 0; i < len(tests); i++ {
		t.Run(tests[i].name, func(t *testing.T) {
			if tests[i].isNIKE {
				for j := tests[i].startHop; j < tests[i].endHop+1; j++ {
					scheme := nikeSchemes.ByName(tests[i].nikeName)
					g := geo.GeometryFromUserForwardPayloadLength(scheme, payloadSize, false, j)
					sphinx := NewSphinx(g)
					if tests[i].isForward {
						testForwardSphinx(t, scheme, sphinx, payload)
					} else {
						testSURB(t, scheme, sphinx, payload)
					}
				}
			} else { // KEM
				for j := tests[i].startHop; j < tests[i].endHop+1; j++ {
					scheme := kemSchemes.ByName(tests[i].kemName)
					g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, payloadSize, false, j)
					sphinx := NewSphinx(g)

					if tests[i].isForward {
						testForwardKEMSphinx(t, scheme, sphinx, payload)
					} else {
						testSURBKEMSphinx(t, scheme, sphinx, payload)
					}
				}
			}
		})
	}
}

type kemNodeParams struct {
	id         [constants.NodeIDLength]byte
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
}

func newKEMNode(require *require.Assertions, mykem kem.Scheme) *kemNodeParams {
	n := new(kemNodeParams)

	_, err := rand.Read(n.id[:])
	require.NoError(err)
	n.publicKey, n.privateKey, err = mykem.GenerateKeyPair()
	require.NoError(err)
	return n
}

func newKEMPathVector(require *require.Assertions, mykem kem.Scheme, nrHops int, isSURB bool) ([]*kemNodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*kemNodeParams, nrHops)
	for i := range nodes {
		nodes[i] = newKEMNode(require, mykem)
	}

	// Assemble the path vector.
	path := make([]*PathHop, nrHops)
	for i := range path {
		path[i] = new(PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].KEMPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Read(recipient.ID[:])
			require.NoError(err, "failed to generate recipient")
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Read(surbReply.ID[:])
				require.NoError(err, "failed to generate surb_reply")
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path
}

func testForwardKEMSphinx(t *testing.T, mykem kem.Scheme, sphinx *Sphinx, testPayload []byte) {
	require := require.New(t)

	for nrHops := 1; nrHops <= sphinx.Geometry().NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the forward sphinx packet.
		nodes, path := newKEMPathVector(require, mykem, nrHops, false)

		// Create the packet.
		payload := []byte(testPayload)
		pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
		require.NoError(err, "NewKEMPacket failed")
		require.Equal(len(pkt), sphinx.Geometry().HeaderLength+sphinx.Geometry().PayloadTagLength+len(payload), "Packet Length")

		// Unwrap the packet, validating the output.
		for i := range nodes {
			b, _, cmds, err := sphinx.Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				require.Equalf(1, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: recipient mismatch", i)

				require.Equalf(b, payload, "Hop %d: payload mismatch", i)
			} else {
				require.Equal(sphinx.Geometry().PacketLength, len(pkt))
				require.Equalf(2, len(cmds), "Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "Hop %d: delay mismatch", i)

				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "Hop %d: cmds[1] is not a NextNodeHop", i)
				require.Equalf(path[i+1].ID, nextNode.ID, "Hop %d: NextNodeHop.ID mismatch", i)

				require.Nil(b, "Hop %d: returned payload", i)
			}
		}
	}
}

func testSURBKEMSphinx(t *testing.T, mykem kem.Scheme, sphinx *Sphinx, testPayload []byte) {
	require := require.New(t)

	require.Equal(sphinx.Geometry().NIKEName, "")
	require.NotEqual(sphinx.Geometry().KEMName, "")
	require.Nil(sphinx.nike)
	require.NotNil(sphinx.kem)

	for nrHops := 1; nrHops <= sphinx.Geometry().NrHops; nrHops++ {
		t.Logf("Testing %d hop(s).", nrHops)

		// Generate the "nodes" and path for the SURB.
		nodes, path := newKEMPathVector(require, mykem, nrHops, true)

		// Create the SURB.
		surb, surbKeys, err := sphinx.NewSURB(rand.Reader, path)
		require.NoError(err, "NewSURB failed")
		require.Equal(sphinx.Geometry().SURBLength, len(surb), "SURB length")

		// Create a reply packet using the SURB.
		payload := []byte(testPayload)
		pkt, firstHop, err := sphinx.NewPacketFromSURB(surb, payload)
		require.NoError(err, "NewPacketFromSURB failed")
		//require.EqualValues(&nodes[0].id, firstHop, "NewPacketFromSURB: 0th hop")
		require.NotNil(firstHop)
		require.NotNil(nodes[0].id)

		// Unwrap the packet, valdiating the output.
		for i := range nodes {
			// There's no sensible way to validate that `tag` is correct.
			b, _, cmds, err := sphinx.Unwrap(nodes[i].privateKey, pkt)
			require.NoErrorf(err, "SURB Hop %d: Unwrap failed", i)

			if i == len(path)-1 {
				require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "SURB Hop %d: recipient mismatch", i)
				require.EqualValuesf(path[i].Commands[1], cmds[1], "SURB Hop %d: surb_reply mismatch", i)

				b, err = sphinx.DecryptSURBPayload(b, surbKeys)
				require.NoError(err, "DecrytSURBPayload")
				require.Equalf(b, payload, "SURB Hop %d: payload mismatch", i)
			} else {
				require.Equal(sphinx.Geometry().PacketLength, len(pkt))
				require.Equalf(2, len(cmds), "SURB Hop %d: Unexpected number of commands", i)
				require.EqualValuesf(path[i].Commands[0], cmds[0], "SURB Hop %d: delay mismatch", i)

				nextNode, ok := cmds[1].(*commands.NextNodeHop)
				require.Truef(ok, "SURB Hop %d: cmds[1] is not a NextNodeHop", i)
				require.Equalf(path[i+1].ID, nextNode.ID, "SURB Hop %d: NextNodeHop.ID mismatch", i)

				require.Nil(b, "SURB Hop %d: returned payload", i)
			}
		}
	}
}
